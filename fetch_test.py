import json, os, time, requests

OID, KEY = os.environ["LC_OID"], os.environ["LC_API_KEY"]
jwt = requests.post("https://jwt.limacharlie.io",
                    data={"oid": OID, "secret": KEY}, timeout=30)
jwt.raise_for_status()

now = int(time.time())
r = requests.get(f"https://api.limacharlie.io/v1/insight/{OID}/detections",
                 headers={"Authorization": f"Bearer {jwt.json()['jwt']}"},
                 params={"start": now - 3 * 86400, "end": now, "limit": 5},
                 timeout=30)
r.raise_for_status()
with open("data/sample.json", "w", encoding="utf-8") as f:
    json.dump(r.json(), f, indent=2)
print("saved data/sample.json")
