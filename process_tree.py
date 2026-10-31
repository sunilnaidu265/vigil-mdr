"""Build a process tree for an incident from LimaCharlie process links (atoms)."""
import ntpath
from adapters.limacharlie import _normalize_time


def _stages(raw):
    detect = raw.get("detect") or {}
    event = detect.get("event") or {}
    if event.get("EVENTS"):
        return [(s.get("event") or {}, s.get("routing") or {}) for s in event["EVENTS"]]
    return [(event, detect.get("routing") or raw.get("routing") or {})]


def _new_node(atom):
    return {"atom": atom, "path": "", "name": "unknown process", "pid": None, "user": "", "command": "",
            "time": None, "parent": None, "rules": set(), "accesses": [], "children": [], "count": 1}


def _fill(node, event, when=None):
    if event.get("FILE_PATH") and not node["path"]:
        node["path"] = event["FILE_PATH"]
        node["name"] = ntpath.basename(event["FILE_PATH"])
    node["pid"] = node["pid"] or event.get("PROCESS_ID")
    node["user"] = node["user"] or event.get("USER_NAME") or ""
    node["command"] = node["command"] or event.get("COMMAND_LINE") or ""
    node["time"] = node["time"] or _normalize_time(event.get("TIMESTAMP")) or when


def _collect(detections):
    nodes = {}

    def get(atom):
        return nodes.setdefault(atom, _new_node(atom))

    def link(child, parent_atom):
        if parent_atom and parent_atom != child["atom"] and not child["parent"]:
            child["parent"] = parent_atom

    for det in detections:
        raw, rule = det["raw"], det["rule"]
        for event, routing in _stages(raw):
            when = _normalize_time(routing.get("event_time"))
            source, target = event.get("SOURCE"), event.get("TARGET")
            if isinstance(source, dict) and isinstance(target, dict):  # one process touching another
                actor = get(source.get("THIS_ATOM") or routing.get("parent"))
                victim = get(target.get("THIS_ATOM") or routing.get("target"))
                _fill(actor, source, when)
                _fill(victim, target, when)
                link(actor, source.get("PARENT_ATOM"))
                link(victim, target.get("PARENT_ATOM"))
                actor["rules"].add(rule)
                access = {"target": victim["name"], "flags": event.get("ACCESS_FLAGS"), "time": when}
                if access not in actor["accesses"]:
                    actor["accesses"].append(access)
                continue
            if not routing.get("this"):
                continue
            node = get(routing["this"])
            _fill(node, event, when)
            parent = event.get("PARENT") or {}
            parent_atom = routing.get("parent") or parent.get("THIS_ATOM")
            link(node, parent_atom)
            if parent_atom and parent_atom != node["atom"]:
                _fill(get(parent_atom), parent)
            if event.get("COMMAND_LINE") or event.get("FILE_PATH"):
                if len(_stages(raw)) == 1:
                    node["rules"].add(rule)
    return nodes


def _merge_identical(children):
    # repeated identical children make the tree long without adding meaning
    merged = {}
    for child in sorted(children, key=lambda c: c["time"] or ""):
        key = (child["path"], child["command"], tuple(sorted(child["rules"])))
        if key in merged and not child["children"] and not child["accesses"]:
            merged[key]["count"] += 1
        else:
            merged.setdefault(key if key not in merged else (key, child["atom"]), child)
    return list(merged.values())


def build_tree(detections):
    nodes = _collect(detections)
    roots = []
    for node in nodes.values():
        parent = nodes.get(node["parent"])
        if parent is None:
            roots.append(node)
        else:
            parent["children"].append(node)

    seen = set()

    def finish(node):
        seen.add(node["atom"])
        node["rules"] = sorted(node["rules"])
        node["children"] = [finish(c) for c in node["children"] if c["atom"] not in seen]
        node["children"] = _merge_identical(node["children"])
        return node

    return [finish(r) for r in sorted(roots, key=lambda n: n["time"] or "")]
