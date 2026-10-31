import json
from adapters import adapt_limacharlie

with open("data/sample.json", encoding="utf-8") as f:
    detections = json.load(f)["detects"]

for det in detections:
    print(json.dumps(adapt_limacharlie(det), indent=2))
