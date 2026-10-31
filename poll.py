"""Fetch LimaCharlie detections, group them into incidents, send those to Ollama,
and store the results in PostgreSQL. Run by a scheduled task."""
import json, logging, os, pathlib, re, sys, time
from datetime import datetime
import requests
import db
from adapters.limacharlie import _redact
from analyze import analyze
from correlate import correlate

BASE = pathlib.Path(__file__).parent
DATA = BASE / "data"
RAW_DIR = DATA / "detections"
STATE_FILE = DATA / "state.json"

API = "https://api.limacharlie.io/v1"
FIRST_RUN_LOOKBACK = 3 * 86400  # seconds of history on the very first run
OVERLAP = 600                   # re-check the last 10 minutes so late detections aren't missed
HOLD = 600                      # wait this long after an incident's last detection, so related ones can join
MAX_PER_RUN = 10                # the rest wait for the next run
PAGE_SIZE = 100

RAW_DIR.mkdir(parents=True, exist_ok=True)
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


def needs_analysis(incident, analyzed, now):
    end = datetime.fromisoformat(incident["end"].replace("Z", "+00:00")).timestamp()
    if now - end < HOLD:
        return False
    return analyzed.get(incident["incident_id"]) != incident["detect_ids"]


def process(incident):
    try:
        record = analyze(incident)
    except requests.RequestException:
        raise  # Ollama is down: leave it unprocessed so a later run retries
    except Exception as e:  # bad model output must not block every later incident
        record = {"incident_id": incident["incident_id"], "host": incident["host"], "score": incident["score"],
                  "ai_status": "failed", "errors": [str(e)]}
    record["detect_ids"] = incident["detect_ids"]
    db.save_analysis(record)
    log.info("analyzed %s score=%s detections=%d -> %s %s", incident["incident_id"], incident["score"],
             len(incident["detect_ids"]), record.get("ai_status"), record.get("analysis", {}).get("verdict", ""))


def main():
    state = load_state()
    now = int(time.time())
    fetched = fetch_detections(state["last_checked"] - OVERLAP, now)
    saved = save_new_detections(fetched)
    state["last_checked"] = now  # raw files are saved, so analysis can resume from them
    save_state(state)

    detections = load_detections()
    incidents = correlate(detections)
    db.sync(incidents, detections)
    analyzed = db.analyzed_detection_sets()
    pending = [i for i in incidents if needs_analysis(i, analyzed, now)]
    log.info("fetched %d, new %d, incidents %d, to analyze %d", len(fetched), saved, len(incidents), len(pending))

    for incident in pending[:MAX_PER_RUN]:  # highest score first
        process(incident)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        log.exception("run failed, will retry on the next run")
        sys.exit(1)
