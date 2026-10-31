"""Group related detections into scored incidents."""
import hashlib
from datetime import datetime
from adapters import adapt_limacharlie
from adapters.limacharlie import _normalize_time, _score_from_priority

PROCESS_WINDOW = 1800  # shared process: link detections up to 30 minutes apart
TIME_WINDOW = 300      # no shared process: link only if within 5 minutes
MAX_SPAN = 3600        # one incident covers at most 1 hour
MAX_EVENTS = 12        # keep the prompt small enough for the model
MAX_COMMAND = 400
MAX_RULES = 6

KNOWN_TOOLS = {r"c:\programdata\orborus\orborus-agent.exe": "Shuffle Orborus agent, the owner's own automation tool"}
LEVEL_SCORES = {"informational": 10, "low": 30, "medium": 50, "high": 70, "critical": 90}
ATOM_KEYS = ("this", "parent", "THIS_ATOM", "PARENT_ATOM")


def _walk(value):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _atoms(det):
    return {node[key] for node in _walk(det) for key in ATOM_KEYS if node.get(key)}


def _timestamp(det):
    text = _normalize_time(det.get("ts")) or "1970-01-01T00:00:00Z"
    return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def _severity(det):
    if det.get("priority") is not None:
        return _score_from_priority(det["priority"])
    return LEVEL_SCORES.get(((det.get("detect_mtd") or {}).get("level") or "").lower(), 40)


def _known_tools(incident):
    paths = {str(p).lower() for e in incident["events"] for p in (e.get("process"), e.get("parent")) if p}
    return {KNOWN_TOOLS[p] for p in paths if p in KNOWN_TOOLS}


def _link(cluster, item):
    span = item["time"] - cluster["start"]
    gap = item["time"] - cluster["end"]
    if span <= MAX_SPAN and gap <= PROCESS_WINDOW and cluster["atoms"] & item["atoms"]:
        return "shared process"
    if span <= MAX_SPAN and gap <= TIME_WINDOW and not cluster["known"] and not item["known"]:
        return "close in time"
    return None


def _cluster(detections):
    items = []
    for det in detections:
        parsed = adapt_limacharlie(det)
        items.append({"det": det, "incident": parsed, "time": _timestamp(det), "atoms": _atoms(det),
                      "known": bool(_known_tools(parsed))})
    items.sort(key=lambda i: i["time"])

    clusters = []
    for item in items:
        open_clusters = [c for c in clusters if c["host"] == item["incident"]["host"]]
        links = [(c, _link(c, item)) for c in open_clusters]
        # a shared process is stronger evidence than timing alone
        match = next((l for l in links if l[1] == "shared process"), None) or next((l for l in links if l[1]), None)
        if match:
            cluster, reason = match
            cluster["members"].append(item)
            cluster["atoms"] |= item["atoms"]
            cluster["end"] = item["time"]
            cluster["known"] = cluster["known"] or item["known"]
            cluster["links"].add(reason)
        else:
            clusters.append({"host": item["incident"]["host"], "members": [item], "atoms": set(item["atoms"]),
                             "start": item["time"], "end": item["time"], "known": item["known"], "links": set()})
    return clusters


def _merge_events(members):
    unique, seen = [], set()
    for member in members:
        for event in member["incident"]["events"]:
            key = (event.get("process"), event.get("command_line"), event.get("target_process"))
            if key in seen:
                continue
            seen.add(key)
            unique.append(dict(event))
    unique.sort(key=lambda e: (not e.get("target_process"), e["time"]))  # cross-process events matter most
    dropped = max(0, len(unique) - MAX_EVENTS)
    kept = sorted(unique[:MAX_EVENTS], key=lambda e: e["time"])

    used = set()
    for number, event in enumerate(kept):
        if event["event_id"] in used:
            event["event_id"] = f"{event['event_id']}-{number}"
        used.add(event["event_id"])
        command = event.get("command_line")
        if isinstance(command, str) and len(command) > MAX_COMMAND:
            event["command_line"] = command[:MAX_COMMAND] + "...[cut]"
    return kept, dropped


def _score(members, events, techniques, rules, known):
    score = max(_severity(m["det"]) for m in members)
    reasons = [f"highest rule severity {score}"]
    if len(techniques) > 1:
        bonus = min(15, 5 * (len(techniques) - 1))
        score += bonus
        reasons.append(f"+{bonus} for {len(techniques)} ATT&CK techniques")
    if len(rules) > 1:
        bonus = min(10, 5 * (len(rules) - 1))
        score += bonus
        reasons.append(f"+{bonus} for {len(rules)} different rules")
    if any("lsass" in str(e.get("target_process", "")).lower() for e in events):
        score += 20
        reasons.append("+20 for access to LSASS")
    if known:
        score -= 30
        reasons.append("-30 for a known tool")
    return max(0, min(100, score)), reasons


def _to_incident(cluster):
    members = cluster["members"]
    events, dropped = _merge_events(members)
    rules = {}
    for member in members:
        det = member["det"]
        rule = rules.setdefault(det.get("cat"), {
            "rule": det.get("cat"), "count": 0, "attack": set(),
            "description": str((det.get("detect_mtd") or {}).get("description") or "")[:200]})
        rule["count"] += 1
        for detection in member["incident"]["detections"]:
            rule["attack"].update(detection["attack"])

    rule_list = sorted(rules.values(), key=lambda r: -r["count"])
    techniques = sorted({t for r in rule_list for t in r["attack"]})
    known = sorted({t for m in members for t in _known_tools(m["incident"])})
    score, reasons = _score(members, events, techniques, rule_list, known)
    for rule in rule_list:
        rule["attack"] = sorted(rule["attack"])

    earliest = members[0]["det"]["detect_id"]
    return {
        "incident_id": "INC-" + hashlib.sha1(str(earliest).encode()).hexdigest()[:8],
        "host": cluster["host"],
        "score": score,
        "detections": [{"rule": r["rule"], "attack": r["attack"]} for r in rule_list],
        "events": events,
        "detect_ids": sorted(str(m["det"]["detect_id"]) for m in members),
        "start": _normalize_time(cluster["start"]),
        "end": _normalize_time(cluster["end"]),
        "linked_by": sorted(cluster["links"]),
        "context": {
            "detection_count": len(members),
            "rules": rule_list[:MAX_RULES],
            "attack_techniques": techniques,
            "score": score,
            "score_reasons": reasons,
            "known_tools": known,
            "events_not_shown": dropped,
        },
    }


def correlate(detections):
    incidents = [_to_incident(cluster) for cluster in _cluster(detections)]
    return sorted(incidents, key=lambda i: -i["score"])
