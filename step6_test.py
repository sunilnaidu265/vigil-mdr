import json, pathlib
from adapters import adapt_limacharlie
from analyze import analyze

with open("data/sample.json", encoding="utf-8") as f:
    detections = json.load(f)["detects"]

det = next(d for d in detections if "Lsass" in d["cat"])
record = analyze(adapt_limacharlie(det))

out = pathlib.Path("data/results"); out.mkdir(parents=True, exist_ok=True)
(out / f"{record['incident_id']}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
print(json.dumps({k: record[k] for k in ("ai_status", "errors", "attack_techniques", "analysis")}, indent=2))
