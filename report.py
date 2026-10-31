"""Build a detailed HTML report from saved detections and verdicts in data/."""
import collections, html, json, pathlib, re
from datetime import datetime
import db
from adapters import adapt_limacharlie
from adapters.limacharlie import _normalize_time

BASE = pathlib.Path(__file__).parent
RAW_DIR = BASE / "data" / "detections"
REPORT_DIR = BASE / "data" / "reports"

URL = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

LOGO = (BASE / "static" / "logo.svg").read_text(encoding="utf-8")

# matches static/style.css; kept inline so a saved report still works on its own
STYLE = """
:root{color-scheme:dark;--edge:rgba(255,255,255,.15);--bright:rgba(255,255,255,.3);--line:rgba(255,255,255,.1);
--glass:rgba(120,175,255,.17);--ink:#f0f5ff;--muted:#a9bddc}
*{box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact}
html{background:#050f26}
body{margin:0;min-height:100vh;color:var(--ink);font:14.5px/1.55 "Segoe UI",Arial,sans-serif;background:
radial-gradient(760px 520px at 8% -8%,rgba(36,112,255,.34),transparent 70%),
radial-gradient(680px 520px at 100% 6%,rgba(0,200,255,.17),transparent 70%),
linear-gradient(165deg,#081a3e 0%,#050f26 62%,#040b1d 100%);background-attachment:fixed}
header{display:flex;justify-content:flex-end;align-items:center;gap:10px;padding:10px 24px;font-size:21px;font-weight:700;
background:linear-gradient(180deg,rgba(255,255,255,.11),rgba(255,255,255,.03));border-bottom:1px solid var(--edge)}
header svg{width:44px;height:44px;border-radius:11px;box-shadow:0 0 20px rgba(79,209,255,.5)}
main{max-width:1100px;margin:0 auto;padding:18px 24px 48px}
h1{font-size:26px;font-weight:600;margin:12px 0;color:#fff}
h2{font-size:19px;margin:32px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--edge)}
h3{font-size:16px;margin:0 0 10px}
table{width:100%;table-layout:fixed;margin:8px 0 16px;font-size:13px;border-collapse:separate;border-spacing:0;
overflow:hidden;background:rgba(4,13,34,.5);border:1px solid var(--edge);border-radius:12px}
th,td{padding:8px 10px;text-align:left;vertical-align:top;overflow-wrap:anywhere;border-bottom:1px solid var(--line)}
tr:last-child td{border-bottom:0}
th{color:#cfe0fb;font-size:13px;font-weight:600;
background:linear-gradient(180deg,rgba(255,255,255,.13),rgba(255,255,255,.04))}
.label{width:170px;color:#cfe0fb;font-weight:600;background:rgba(255,255,255,.06)}
code{font:12px Consolas,monospace;color:#d8ecff;white-space:pre-wrap;overflow-wrap:anywhere}
.case{margin:16px 0;padding:18px;background:linear-gradient(150deg,var(--glass),rgba(255,255,255,.035));
border:1px solid var(--edge);border-radius:16px;box-shadow:0 14px 34px rgba(0,0,0,.38),inset 0 1px 0 var(--bright)}
.note{padding:10px 14px;font-size:13px;color:#ffe6ac;background:rgba(255,203,107,.1);
border:1px solid rgba(255,203,107,.35);border-radius:12px}
@media print{html,body{background:#071631}body{background-attachment:scroll}
header{background:#0d2452}header svg{box-shadow:none}
.case{background:#10294f;box-shadow:none;break-inside:auto}
table{overflow:visible;background:#0b1c3f}tr{break-inside:avoid}th{background:#183268}
.label{background:#142c5a}.note{background:#2a2a24}}
"""


def esc(value):
    return html.escape("" if value is None else str(value))


def code(value):
    return f"<code>{esc(value)}</code>" if value not in (None, "") else ""


def walk_dicts(value):
    if isinstance(value, dict):
        yield value
        for item in value.values():
            yield from walk_dicts(item)
    elif isinstance(value, list):
        for item in value:
            yield from walk_dicts(item)


def load_cases(incidents):
    by_detection = {d: record for record in incidents for d in record.get("detect_ids", [])}
    cases = []
    for path in RAW_DIR.glob("*.json"):
        det = json.loads(path.read_text(encoding="utf-8"))
        cases.append({"det": det, "incident": adapt_limacharlie(det),
                      "result": by_detection.get(str(det.get("detect_id")), {}),
                      "time": _normalize_time(det.get("ts")) or "unknown"})
    return sorted(cases, key=lambda c: c["time"])


def incident_html(number, record):
    analysis = record.get("analysis") or {}
    context = record.get("context") or {}
    fields = [
        ("Score", esc(record.get("score"))), ("Period (UTC)", esc(f"{record.get('start')} to {record.get('end')}")),
        ("Host", esc(record.get("host"))), ("Detections", esc(len(record.get("detect_ids", [])))),
        ("Grouped by", esc(", ".join(record.get("linked_by", [])) or "single detection")),
        ("Rules", esc(", ".join(r["rule"] for r in context.get("rules", [])))),
        ("ATT&CK", esc(", ".join(context.get("attack_techniques", [])))),
        ("Score reasons", esc("; ".join(context.get("score_reasons", [])))),
        ("Known tools", esc(", ".join(context.get("known_tools", [])))),
        ("AI status", esc(record.get("ai_status"))), ("AI verdict", esc(analysis.get("verdict", ""))),
        ("AI confidence", esc(analysis.get("confidence", ""))), ("AI summary", esc(analysis.get("summary", ""))),
        ("AI actions", "<br>".join(esc(a) for a in analysis.get("recommended_actions", []))),
    ]
    rows = "".join(f"<tr><td class='label'>{label}</td><td>{value}</td></tr>" for label, value in fields)
    return f"<div class='case'><h3>{number}. {esc(record.get('incident_id'))}</h3><table>{rows}</table></div>"


def collect_iocs(cases):
    files, commands, users = {}, {}, collections.Counter()
    hosts, urls, ips = {}, collections.Counter(), collections.Counter()

    def seen(store, key, when, **extra):
        item = store.setdefault(key, {"first": when, "last": when, "count": 0, **extra})
        item["first"], item["last"] = min(item["first"], when), max(item["last"], when)
        item["count"] += 1

    for case in cases:
        when = case["time"]
        routing = case["det"].get("routing") or {}
        seen(hosts, routing.get("hostname") or case["incident"]["host"], when,
             int_ip=routing.get("int_ip"), ext_ip=routing.get("ext_ip"))
        for node in walk_dicts(case["det"].get("detect") or {}):
            if node.get("FILE_PATH"):
                seen(files, (node["FILE_PATH"], node.get("HASH") or ""), when)
            if node.get("COMMAND_LINE"):
                seen(commands, node["COMMAND_LINE"], when)
                urls.update(URL.findall(node["COMMAND_LINE"]))
                ips.update(IPV4.findall(node["COMMAND_LINE"]))
            if node.get("USER_NAME"):
                users[node["USER_NAME"]] += 1
    return files, commands, users, hosts, urls, ips


def table(headers, rows):
    head = "".join(f"<th>{esc(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><tr>{head}</tr>{body or f'<tr><td colspan={len(headers)}>None observed</td></tr>'}</table>"


def case_html(number, case):
    det, incident, result = case["det"], case["incident"], case["result"]
    analysis = result.get("analysis") or {}
    attack = incident["detections"][0]["attack"] if incident["detections"] else []
    routing = det.get("routing") or {}
    fields = [
        ("Detected (UTC)", esc(case["time"])), ("Host", esc(incident["host"])),
        ("Internal / external IP", esc(f"{routing.get('int_ip', '')} / {routing.get('ext_ip', '')}")),
        ("Rule", esc(incident["detections"][0]["rule"] if incident["detections"] else "")),
        ("ATT&CK", esc(", ".join(attack))), ("Score", esc(incident["score"])),
        ("AI status", esc(result.get("ai_status", "not analyzed yet"))),
        ("AI verdict", esc(analysis.get("verdict", ""))), ("AI confidence", esc(analysis.get("confidence", ""))),
        ("AI summary", esc(analysis.get("summary", ""))),
        ("AI actions", "<br>".join(esc(a) for a in analysis.get("recommended_actions", []))),
        ("Detection ID", code(det.get("detect_id"))),
    ]
    rows = "".join(f"<tr><td class='label'>{label}</td><td>{value}</td></tr>" for label, value in fields)
    events = [[esc(e["time"]), code(e.get("process")), code(e.get("parent")), esc(e.get("user")),
               code(e.get("command_line")), code(e.get("target_process"))] for e in incident["events"]]
    return (f"<div class='case'><h3>{number}. {esc(det.get('cat'))}</h3><table>{rows}</table>"
            + table(["Time (UTC)", "Process", "Parent", "User", "Command line", "Target"], events) + "</div>")


def build(cases, incidents):
    files, commands, users, hosts, urls, ips = collect_iocs(cases)
    verdicts = collections.Counter((c["result"].get("analysis") or {}).get("verdict", "not analyzed yet") for c in cases)
    rules = collections.defaultdict(lambda: {"count": 0, "attack": set()})
    for case in cases:
        rule = rules[case["det"].get("cat")]
        rule["count"] += 1
        for item in case["incident"]["detections"]:
            rule["attack"].update(item["attack"])

    generated = datetime.now().strftime("%Y-%m-%d %H:%M")
    first, last = (cases[0]["time"], cases[-1]["time"]) if cases else ("", "")
    parts = [
        f"<h1>Vigil MDR Detection Report</h1><p>Generated {esc(generated)} (local time). "
        f"Detections from {esc(first)} to {esc(last)} (UTC).</p>",
        "<p class='note'>Indicators are activity observed on the lab sandbox, including deliberate "
        "Atomic Red Team tests and normal tools. They are not confirmed malicious. "
        "Secrets in command lines are masked as [REDACTED].</p>",
        "<h2>Summary</h2>",
        table(["Total detections", "Rules fired", "Verdicts"],
              [[len(cases), len(rules), esc(", ".join(f"{k}: {v}" for k, v in verdicts.items()))]]),
        f"<h2>Incidents ({len(incidents)}, highest score first)</h2>",
        *[incident_html(i, record) for i, record in enumerate(incidents, 1)],
        "<h2>Detections by rule</h2>",
        table(["Rule", "Count", "ATT&CK"],
              [[esc(k), v["count"], esc(", ".join(sorted(v["attack"])))]
               for k, v in sorted(rules.items(), key=lambda kv: -kv[1]["count"])]),
        "<h2>Indicators: hosts</h2>",
        table(["Host", "Internal IP", "External IP", "Detections", "First seen", "Last seen"],
              [[esc(k), esc(v["int_ip"]), esc(v["ext_ip"]), v["count"], esc(v["first"]), esc(v["last"])]
               for k, v in hosts.items()]),
        "<h2>Indicators: users</h2>",
        table(["User", "Times seen"], [[esc(k), v] for k, v in users.most_common()]),
        "<h2>Indicators: files and hashes</h2>",
        table(["File path", "Hash", "Seen", "First seen", "Last seen"],
              [[code(k[0]), code(k[1]), v["count"], esc(v["first"]), esc(v["last"])]
               for k, v in sorted(files.items(), key=lambda kv: -kv[1]["count"])]),
        "<h2>Indicators: URLs and IPs in command lines</h2>",
        table(["Value", "Seen"], [[code(k), v] for k, v in (urls + ips).most_common()]),
        "<h2>Indicators: command lines</h2>",
        table(["Command line", "Seen", "First seen", "Last seen"],
              [[code(k), v["count"], esc(v["first"]), esc(v["last"])]
               for k, v in sorted(commands.items(), key=lambda kv: kv[1]["first"])]),
        "<h2>Detection timeline</h2>",
        *[case_html(i, case) for i, case in enumerate(cases, 1)],
    ]
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>Vigil MDR Report</title>"
            f"<style>{STYLE}</style></head><body><header>{LOGO}<span>Vigil MDR</span></header>"
            f"<main>{''.join(parts)}</main></body></html>")


if __name__ == "__main__":
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    incidents = db.load_incidents()
    cases = load_cases(incidents)
    path = REPORT_DIR / f"vigil-report-{datetime.now():%Y%m%d-%H%M}.html"
    path.write_text(build(cases, incidents), encoding="utf-8")
    print(f"{len(cases)} detections, {len(incidents)} incidents -> {path}")
