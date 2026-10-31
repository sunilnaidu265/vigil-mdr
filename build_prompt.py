"""Build the system prompt for one incident: core rules + only the playbooks it needs.

A small local model (qwen3:4b) cannot hold every playbook at once, so we pick the
relevant ones from the incident's MITRE ATT&CK technique IDs.
"""
import pathlib

PROMPTS = pathlib.Path(__file__).parent / "prompts"
PLAYBOOKS = PROMPTS / "playbooks"

# kill-chain order = order the playbooks appear in the prompt
ORDER = ["initial_access", "execution", "persistence", "privilege_escalation",
         "defense_evasion", "credential_access", "discovery_lateral", "c2_exfil",
         "impact_ransomware", "linux", "forensics"]

# when we must trim to max_playbooks, keep the most severe / most specific first
PRIORITY = ["forensics", "impact_ransomware", "linux", "credential_access", "discovery_lateral",
            "c2_exfil", "persistence", "privilege_escalation", "defense_evasion",
            "execution", "initial_access"]

# parent technique ID -> playbooks
TECHNIQUE_MAP = {
    # initial access
    "T1566": ["initial_access"], "T1189": ["initial_access"], "T1190": ["initial_access"],
    "T1133": ["initial_access"], "T1078": ["initial_access", "discovery_lateral"],
    "T1204": ["initial_access", "execution"], "T1091": ["initial_access"],
    # execution
    "T1059": ["execution"], "T1047": ["execution", "discovery_lateral"], "T1106": ["execution"],
    "T1129": ["execution"], "T1203": ["execution", "initial_access"], "T1569": ["execution", "persistence"],
    # persistence
    "T1547": ["persistence"], "T1053": ["persistence", "execution"], "T1543": ["persistence"],
    "T1546": ["persistence"], "T1136": ["persistence"], "T1098": ["persistence"],
    "T1505": ["persistence", "initial_access"], "T1037": ["persistence"], "T1574": ["persistence", "defense_evasion"],
    # privilege escalation
    "T1548": ["privilege_escalation"], "T1134": ["privilege_escalation"], "T1068": ["privilege_escalation"],
    # defense evasion
    "T1070": ["defense_evasion"], "T1562": ["defense_evasion"], "T1036": ["defense_evasion"],
    "T1055": ["defense_evasion", "privilege_escalation"], "T1027": ["defense_evasion", "execution"],
    "T1218": ["defense_evasion", "execution"], "T1112": ["defense_evasion"], "T1140": ["defense_evasion"],
    "T1564": ["defense_evasion"], "T1497": ["defense_evasion"], "T1620": ["defense_evasion"],
    # credential access
    "T1003": ["credential_access"], "T1110": ["credential_access"], "T1558": ["credential_access"],
    "T1555": ["credential_access"], "T1552": ["credential_access"], "T1539": ["credential_access"],
    "T1056": ["credential_access"], "T1557": ["credential_access"],
    # discovery + lateral movement
    "T1087": ["discovery_lateral"], "T1069": ["discovery_lateral"], "T1018": ["discovery_lateral"],
    "T1082": ["discovery_lateral"], "T1016": ["discovery_lateral"], "T1033": ["discovery_lateral"],
    "T1049": ["discovery_lateral"], "T1057": ["discovery_lateral"], "T1083": ["discovery_lateral"],
    "T1135": ["discovery_lateral"], "T1046": ["discovery_lateral"], "T1482": ["discovery_lateral"],
    "T1021": ["discovery_lateral"], "T1570": ["discovery_lateral"], "T1550": ["discovery_lateral", "credential_access"],
    "T1563": ["discovery_lateral"], "T1210": ["discovery_lateral"],
    # C2 + exfiltration
    "T1071": ["c2_exfil"], "T1105": ["c2_exfil", "execution"], "T1219": ["c2_exfil"], "T1572": ["c2_exfil"],
    "T1090": ["c2_exfil"], "T1573": ["c2_exfil"], "T1095": ["c2_exfil"], "T1568": ["c2_exfil"],
    "T1041": ["c2_exfil"], "T1048": ["c2_exfil"], "T1567": ["c2_exfil"], "T1560": ["c2_exfil"],
    "T1074": ["c2_exfil"], "T1132": ["c2_exfil"],
    # impact
    "T1486": ["impact_ransomware"], "T1490": ["impact_ransomware"], "T1489": ["impact_ransomware"],
    "T1485": ["impact_ransomware"], "T1561": ["impact_ransomware"], "T1491": ["impact_ransomware"],
    "T1529": ["impact_ransomware"],
}

FORENSIC_SOURCES = ("prefetch", "amcache", "shimcache", "mft", "usn", "evtx", "registry",
                    "srum", "lnk", "jumplist", "shellbag", "browser", "auth.log", "syslog")


def select_playbooks(incident, deep=False, max_playbooks=4):
    chosen = set()
    for det in incident.get("detections", []):
        for tid in det.get("attack", []):
            chosen.update(TECHNIQUE_MAP.get(tid.split(".")[0].upper(), []))

    if not chosen:
        chosen.add("execution")                      # sensible default for endpoint alerts

    if str(incident.get("os", "")).lower().startswith("linux"):
        chosen.add("linux")

    has_artifacts = any(
        any(src in str(ev.get("artifact", ev.get("source", ""))).lower() for src in FORENSIC_SOURCES)
        for ev in incident.get("events", [])
    )
    if deep or has_artifacts:
        chosen.add("forensics")

    if not deep:
        chosen = set([p for p in PRIORITY if p in chosen][:max_playbooks])
    return [p for p in ORDER if p in chosen]


def build_system_prompt(incident, deep=False, max_playbooks=4):
    core = (PROMPTS / "core.md").read_text(encoding="utf-8")
    names = select_playbooks(incident, deep=deep, max_playbooks=max_playbooks)
    books = [(PLAYBOOKS / f"{n}.md").read_text(encoding="utf-8") for n in names]
    return core + "\n" + "\n".join(books), names


if __name__ == "__main__":
    import json, sys
    inc = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    deep = "--deep" in sys.argv
    prompt, names = build_system_prompt(inc, deep=deep)
    print("playbooks:", names)
    print("prompt length:", len(prompt), "chars (~", len(prompt) // 4, "tokens)")
