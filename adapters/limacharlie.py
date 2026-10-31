from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List


SECRET_ARG = re.compile(
    r"(--?(?:auth|token|password|passwd|pwd|secret|api[-_]?key)(?:=|\s+))(\"[^\"]*\"|'[^']*'|\S+)",
    re.IGNORECASE,
)


def _redact(command_line: Any) -> Any:
    if not isinstance(command_line, str):
        return command_line
    return SECRET_ARG.sub(r"\1[REDACTED]", command_line)


def _normalize_time(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1_000_000_000_000:
            ts = ts / 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, str):
        s = value.strip()
        if not s:
            return None
        try:
            ts = float(s)
            if abs(ts) > 1_000_000_000_000:
                ts = ts / 1000.0
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            try:
                dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
                return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            except ValueError:
                return None
    return None


def _event_id(prefix: str, raw: Dict[str, Any]) -> str:
    for key in ("PROCESS_ID", "PARENT_PROCESS_ID", "THIS_ATOM", "event_id"):
        value = raw.get(key)
        if value not in (None, ""):
            return f"{prefix}-{value}"
    return f"{prefix}-event"


def _build_event(
    event: Dict[str, Any],
    name: str,
    *,
    parent: Dict[str, Any] | None = None,
    time_override: str | None = None,
) -> Dict[str, Any]:
    command_line = event.get("COMMAND_LINE")
    process_path = event.get("FILE_PATH") or (command_line.split()[0] if isinstance(command_line, str) else "")
    proc = {
        "event_id": _event_id(name, event),
        "time": time_override or _normalize_time(event.get("TIMESTAMP") or event.get("time") or event.get("event_time") or event.get("ts")) or "1970-01-01T00:00:00Z",
        "process": process_path,
        "parent": parent.get("FILE_PATH") if parent else None,
        "command_line": _redact(command_line),
        "user": event.get("USER_NAME") or event.get("user"),
    }
    if event.get("NETWORK"):
        proc["network"] = event["NETWORK"]
    if event.get("FILE_WRITE"):
        proc["file_write"] = event["FILE_WRITE"]
    return proc


def _score_from_priority(value: Any) -> int:
    if value is None:
        return 75
    if isinstance(value, str):
        try:
            value = int(value)
        except ValueError:
            return 75
    if value <= 0:
        return 0
    if value >= 6:
        return min(100, int(value * 10))
    mapping = {1: 95, 2: 85, 3: 75, 4: 60, 5: 40}
    return mapping.get(int(value), 75)


def _parse_attack_techniques(payload: Dict[str, Any]) -> List[str]:
    techniques: List[str] = []
    detect_mtd = payload.get("detect_mtd") or {}
    for candidate in (
        detect_mtd.get("tags"),
        payload.get("rule_tags"),
        detect_mtd.get("mitre"),
        payload.get("mitre"),
        payload.get("cat"),
        payload.get("source_rule"),
    ):
        if candidate:
            techniques.extend(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", str(candidate).upper()))
    return sorted(set(techniques))


def adapt_limacharlie(payload: Dict[str, Any]) -> Dict[str, Any]:
    detect = payload.get("detect") or {}
    event = detect.get("event") or {}
    parent = event.get("PARENT") or {}
    routing = payload.get("routing") or detect.get("routing") or {}

    event_time = (
        _normalize_time(event.get("TIMESTAMP"))
        or _normalize_time(event.get("time"))
        or _normalize_time(event.get("event_time"))
        or _normalize_time(routing.get("event_time"))
        or _normalize_time(payload.get("ts"))
        or "1970-01-01T00:00:00Z"
    )
    parent_time = (
        _normalize_time(parent.get("TIMESTAMP"))
        or _normalize_time(parent.get("time"))
        or _normalize_time(parent.get("event_time"))
        or _normalize_time(routing.get("event_time"))
        or _normalize_time(payload.get("ts"))
        or "1970-01-01T00:00:00Z"
    )

    events: List[Dict[str, Any]] = []
    stages = event.get("EVENTS")
    if stages:  # stateful rules wrap each matched event in EVENTS
        for number, stage in enumerate(stages):
            stage_event = stage.get("event") or {}
            stage_routing = stage.get("routing") or {}
            stage_parent = stage_event.get("PARENT") or {}
            stage_time = _normalize_time(stage_routing.get("event_time")) or event_time
            if stage_parent:
                events.append(_build_event(
                    stage_parent,
                    f"lc-stage{number}-parent",
                    time_override=_normalize_time(stage_parent.get("TIMESTAMP")) or stage_time,
                ))
            built = _build_event(stage_event, f"lc-stage{number}", parent=stage_parent, time_override=stage_time)
            built["event_type"] = stage_routing.get("event_type")
            source = stage_event.get("SOURCE")
            target = stage_event.get("TARGET")
            if isinstance(source, dict):  # cross-process events describe both processes
                built["process"] = source.get("FILE_PATH") or built["process"]
                built["command_line"] = _redact(source.get("COMMAND_LINE")) or built["command_line"]
                built["user"] = source.get("USER_NAME") or built["user"]
            if isinstance(target, dict):
                built["target_process"] = target.get("FILE_PATH")
            if stage_event.get("ACCESS_FLAGS") is not None:
                built["access_flags"] = stage_event["ACCESS_FLAGS"]
            events.append(built)
    else:
        if parent:
            events.append(_build_event(parent, "lc-parent", parent=None, time_override=parent_time))
        events.append(_build_event(event, "lc-process", parent=parent, time_override=event_time))

    detections = []
    attack = _parse_attack_techniques(payload)
    rule = payload.get("source_rule") or payload.get("cat") or "limacharlie-detection"
    if attack:
        detections.append({"rule": rule, "attack": attack})
    elif rule:
        detections.append({"rule": rule, "attack": []})

    host = routing.get("hostname") or event.get("HOST_NAME") or payload.get("host") or "unknown-host"
    incident_id = payload.get("detect_id") or payload.get("source") or f"LC-{routing.get('event_id', 'unknown')}"
    score = _score_from_priority(payload.get("priority"))

    return {
        "incident_id": incident_id,
        "host": host,
        "score": score,
        "detections": detections,
        "events": sorted(events, key=lambda item: item["time"]),
    }


def load_json_file(path: str | None) -> Dict[str, Any]:
    if path is None:
        raise ValueError("A file path is required")
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Convert a LimaCharlie detection JSON into the analyzer incident format.")
    parser.add_argument("file", help="Path to a LimaCharlie detection JSON file")
    args = parser.parse_args()
    incident = adapt_limacharlie(load_json_file(args.file))
    print(json.dumps(incident, indent=2))
