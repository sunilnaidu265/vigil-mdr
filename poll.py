"""Fetch LimaCharlie detections, group them into incidents, and send those to Ollama.
Run by a scheduled task."""
import json, logging, os, pathlib, re, sys, time
from datetime import datetime
import requests
from adapters.limacharlie import _redact
from analyze import analyze
from correlate import correlate

BASE = pathlib.Path(__file__).parent
DATA = BASE / "data"
RAW_DIR = DATA / "detections"
INCIDENT_DIR = DATA / "incidents"
STATE_FILE = DATA / "state.json"

API = "https://api.limacharlie.io/v1"
FIRST_RUN_LOOKBACK = 3 * 86400  # seconds of history on the very first run
OVERLAP = 600                   # re-check the last 10 minutes so late detections aren't missed
HOLD = 600                      # wait this long after an incident's last detection, so related ones can join
MAX_PER_RUN = 10                # the rest wait for the next run
PAGE_SIZE = 100

RAW_DIR.mkdir(parents=True, exist_ok=True)
INCIDENT_DIR.mkdir(parents=True, exist_ok=True)
logging.basicConfig(filename=DATA / "poll.log", encoding="utf-8", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("poll")


def load_state():
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    return {"last_checked": int(time.time()) - FIRST_RUN_LOOKBACK}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state), encoding="utf-8")


def get_token():
    r = requests.post("https://jwt.limacharlie.io", timeout=30,
                      data={"oid": os.environ["LC_OID"], "secret": os.environ["LC_API_KEY"]})
    r.raise_for_status()
    return r.json()["jwt"]


def fetch_detections(start, end):
    headers = {"Authorization": f"Bearer {get_token()}"}
    url = f"{API}/insight/{os.environ['LC_OID']}/detections"
    params = {"start": start, "end": end, "limit": PAGE_SIZE}
    found = {}
    while True:
        r = requests.get(url, headers=headers, params=params, timeout=60)
        r.raise_for_status()
        body = r.json()
        page = body.get("detects") or []
        before = len(found)
        found.update({d["detect_id"]: d for d in page})
        cursor = body.get("next_cursor")
        if not cursor or len(found) == before:
            break
        params["cursor"] = cursor
    return list(found.values())


def redact_all(value):
    # raw files are kept for reference, so they must not hold secrets either
    if isinstance(value, dict):
        return {k: redact_all(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_all(v) for v in value]
    return _redact(value)


def safe_name(value):
    return re.sub(r"[^\w.-]", "_", str(value)) + ".json"


def save_new_detections(detections):
    saved = 0
    for det in detections:
        path = RAW_DIR / safe_name(det["detect_id"])
        if not path.exists():
            path.write_text(json.dumps(redact_all(det), indent=2), encoding="utf-8")
            saved += 1
    return saved


def load_detections():
    return [json.loads(p.read_text(encoding="utf-8")) for p in RAW_DIR.glob("*.json")]


def needs_analysis(incident, now):
    end = datetime.fromisoformat(incident["end"].replace("Z", "+00:00")).timestamp()
    if now - end < HOLD:
        return False
    path = INCIDENT_DIR / safe_name(incident["incident_id"])
    if not path.exists():
        return True
    return json.loads(path.read_text(encoding="utf-8")).get("detect_ids") != incident["detect_ids"]


def process(incident):
    try:
        record = analyze(incident)
    except requests.RequestException:
        raise  # Ollama is down: leave it unprocessed so a later run retries
    except Exception as e:  # bad model output must not block every later incident
        record = {"incident_id": incident["incident_id"], "host": incident["host"], "score": incident["score"],
                  "ai_status": "failed", "errors": [str(e)]}
    record.update({k: incident[k] for k in ("detect_ids", "start", "end", "linked_by", "context")})
    (INCIDENT_DIR / safe_name(incident["incident_id"])).write_text(json.dumps(record, indent=2), encoding="utf-8")
    log.info("analyzed %s score=%s detections=%d -> %s %s", incident["incident_id"], incident["score"],
             len(incident["detect_ids"]), record.get("ai_status"), record.get("analysis", {}).get("verdict", ""))


def remove_stale(incidents):
    # regrouping can replace an incident, so its old result must go
    current = {safe_name(i["incident_id"]) for i in incidents}
    for path in INCIDENT_DIR.glob("*.json"):
        if path.name not in current:
            path.unlink()


def main():
    state = load_state()
    now = int(time.time())
    fetched = fetch_detections(state["last_checked"] - OVERLAP, now)
    saved = save_new_detections(fetched)
    state["last_checked"] = now  # raw files are saved, so analysis can resume from them
    save_state(state)

    incidents = correlate(load_detections())
    remove_stale(incidents)
    pending = [i for i in incidents if needs_analysis(i, now)]
    log.info("fetched %d, new %d, incidents %d, to analyze %d", len(fetched), saved, len(incidents), len(pending))

    for incident in pending[:MAX_PER_RUN]:  # highest score first
        process(incident)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        log.exception("run failed, will retry on the next run")
        sys.exit(1)
