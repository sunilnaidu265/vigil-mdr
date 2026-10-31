import json, sys, pathlib, requests
from validate import validate
from build_prompt import build_system_prompt
from defang import defang_obj

BASE = pathlib.Path(__file__).parent
MODEL = "qwen3:4b"
URL = "http://localhost:11434/api/chat"
SCHEMA = json.loads((BASE / "schema/verdict.schema.json").read_text(encoding="utf-8"))
CONTEXT_NOTE = ("<context> comes from Vigil, not the host, so it is trusted: rules fired, ATT&CK techniques, "
                "score and known tools. The events are inside <evidence>.")


def call_llm(messages):
    r = requests.post(URL, json={
        "model": MODEL, "stream": False, "think": False, "keep_alive": "30m",
        "format": SCHEMA,
        "options": {"temperature": 0, "num_ctx": 8192},
        "messages": messages,
    }, timeout=600)
    r.raise_for_status()
    return r.json()["message"]["content"]


def analyze(incident, deep=False):
    system_prompt, playbooks = build_system_prompt(incident, deep=deep)
    # only events are evidence; trusted Vigil data stays apart from attacker-controlled text
    evidence = json.dumps(incident["events"], indent=1)
    context = json.dumps(incident.get("context", {}), indent=1)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"{CONTEXT_NOTE}\n<context>\n{context}\n</context>\n<evidence>\n{evidence}\n</evidence>"},
    ]
    raw = call_llm(messages)
    result = json.loads(raw)
    errors = validate(result, incident, SCHEMA)

    if errors:  # one retry with the errors
        messages += [
            {"role": "assistant", "content": raw},
            {"role": "user", "content": "Fix these errors and return corrected JSON: " + "; ".join(errors)},
        ]
        raw = call_llm(messages)
        result = json.loads(raw)
        errors = validate(result, incident, SCHEMA)

    result = defang_obj(result)  # guarantee IOC masking even if the model missed some

    # fields computed by code, not by the model
    return {
        "incident_id": incident["incident_id"],
        "host": incident["host"],
        "score": incident["score"],
        "attack_techniques": sorted({t for d in incident["detections"] for t in d.get("attack", [])}),
        "timeline": sorted(incident["events"], key=lambda e: e["time"]),
        "model": MODEL,
        "playbooks": playbooks,
        "ai_status": "failed" if errors else "ok",
        "errors": errors,
        "analysis": result,
    }


if __name__ == "__main__":
    incident = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
    record = analyze(incident)
    out = BASE / "out" / f"{incident['incident_id']}.json"
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    print(json.dumps(record["analysis"], indent=2))
    print(f"\nai_status={record['ai_status']}  saved -> {out}")