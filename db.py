"""PostgreSQL storage for Vigil. Run `python db.py` to create the tables."""
import os, pathlib
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from adapters.limacharlie import _normalize_time, _parse_attack_techniques

BASE = pathlib.Path(__file__).parent


def connect():
    return psycopg.connect(host="localhost", port=5432, dbname="vigil", user="vigil",
                           password=os.environ["VIGIL_DB_PASSWORD"], row_factory=dict_row,
                           options="-c TimeZone=UTC")  # every time shown is labelled UTC


def init_db():
    with connect() as conn:
        conn.execute((BASE / "schema.sql").read_text(encoding="utf-8"))


def _save_incident(conn, incident):
    conn.execute("""
        INSERT INTO incidents (incident_id, host, score, start_time, end_time, linked_by, context)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (incident_id) DO UPDATE SET
            host = EXCLUDED.host, score = EXCLUDED.score, start_time = EXCLUDED.start_time,
            end_time = EXCLUDED.end_time, linked_by = EXCLUDED.linked_by,
            context = EXCLUDED.context, updated_at = now()
        """, (incident["incident_id"], incident["host"], incident["score"], incident["start"], incident["end"],
              incident["linked_by"], Jsonb(incident["context"])))
    conn.execute("DELETE FROM events WHERE incident_id = %s", (incident["incident_id"],))
    for event in incident["events"]:
        conn.execute("""
            INSERT INTO events (incident_id, event_id, event_time, event_type, process, parent,
                                command_line, username, target_process, access_flags)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (incident["incident_id"], event["event_id"], event["time"], event.get("event_type"),
                  event.get("process"), event.get("parent"), event.get("command_line"), event.get("user"),
                  event.get("target_process"), event.get("access_flags")))


def _save_detection(conn, det, incident_id):
    conn.execute("""
        INSERT INTO detections (detect_id, incident_id, rule, host, detected_at, priority, level, attack, raw)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (detect_id) DO UPDATE SET incident_id = EXCLUDED.incident_id
        """, (det["detect_id"], incident_id, det.get("cat"), (det.get("routing") or {}).get("hostname"),
              _normalize_time(det.get("ts")), det.get("priority"), (det.get("detect_mtd") or {}).get("level"),
              _parse_attack_techniques(det), Jsonb(det)))


def sync(incidents, detections):
    """Make the incident, event and detection tables match the latest grouping."""
    owner = {d: i["incident_id"] for i in incidents for d in i["detect_ids"]}
    with connect() as conn:
        for incident in incidents:
            _save_incident(conn, incident)
        for det in detections:
            _save_detection(conn, det, owner.get(str(det["detect_id"])))
        # regrouping can replace an incident, so its old rows must go
        conn.execute("DELETE FROM incidents WHERE NOT (incident_id = ANY(%s))", ([i["incident_id"] for i in incidents],))


def analyzed_detection_sets():
    with connect() as conn:
        rows = conn.execute("""
            SELECT DISTINCT ON (incident_id) incident_id, detect_ids
            FROM analyses ORDER BY incident_id, created_at DESC, id DESC
            """).fetchall()
    return {r["incident_id"]: r["detect_ids"] for r in rows}


def save_analysis(record):
    analysis = record.get("analysis") or {}
    with connect() as conn:
        conn.execute("""
            INSERT INTO analyses (incident_id, detect_ids, model, ai_status, verdict, confidence, severity, summary,
                                  claims, attack_chain, recommended_actions, errors, playbooks,
                                  iocs, evidence_requests)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (record["incident_id"], record["detect_ids"], record.get("model"), record["ai_status"],
                  analysis.get("verdict"), analysis.get("confidence"), analysis.get("severity"), analysis.get("summary"),
                  Jsonb(analysis.get("claims", [])), Jsonb(analysis.get("attack_chain", [])),
                  Jsonb(analysis.get("recommended_actions", [])), Jsonb(record.get("errors", [])),
                  record.get("playbooks", []), Jsonb(analysis.get("iocs", [])),
                  Jsonb(analysis.get("evidence_requests", []))))


def _review_status(row):
    # new detections mean the last decision no longer covers the whole incident
    changed = bool(row["decision"]) and row["decision"] != "reopened" and row["reviewed_ids"] != row["detect_ids"]
    open_now = not row["decision"] or row["decision"] == "reopened" or changed
    return {"status": "open" if open_now else row["decision"], "changed_since_review": changed,
            "review_note": row["note"] or "", "reviewed_at": row["reviewed_at"]}


def save_review(incident_id, decision, note, detect_ids, reason="", before=None, after=None):
    with connect() as conn:
        conn.execute("""
            INSERT INTO reviews (incident_id, decision, note, detect_ids, reason, summary_before, summary_after)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (incident_id, decision, note, detect_ids, reason, before, after))


def load_metrics():
    latest_review = """LEFT JOIN LATERAL (
        SELECT * FROM reviews x WHERE x.incident_id = {0}.incident_id
        ORDER BY x.created_at DESC, x.id DESC LIMIT 1) r ON true"""
    with connect() as conn:
        return {
            "per_day": conn.execute("""
                SELECT to_char(i.start_time, 'YYYY-MM-DD') AS day, COALESCE(a.severity, 'unrated') AS severity,
                       count(*) AS total
                FROM incidents i
                LEFT JOIN LATERAL (SELECT severity FROM analyses x WHERE x.incident_id = i.incident_id
                                   ORDER BY x.created_at DESC, x.id DESC LIMIT 1) a ON true
                GROUP BY 1, 2 ORDER BY 1 DESC
                """).fetchall(),
            "detect_seconds": conn.execute("""
                SELECT avg(extract(epoch FROM detected_at)
                           - (raw->'routing'->>'event_time')::double precision / 1000) AS seconds
                FROM detections WHERE raw->'routing'->>'event_time' ~ '^[0-9]+$'
                """).fetchone()["seconds"],
            "triage_seconds": conn.execute("""
                SELECT avg(extract(epoch FROM r.first_review - a.first_analysis)) AS seconds
                FROM (SELECT incident_id, min(created_at) AS first_analysis FROM analyses GROUP BY 1) a
                JOIN (SELECT incident_id, min(created_at) AS first_review FROM reviews
                      WHERE decision IN ('approved', 'edited', 'rejected', 'closed') GROUP BY 1) r USING (incident_id)
                """).fetchone()["seconds"],
            "decisions": conn.execute(f"""
                SELECT r.decision, count(*) AS total FROM incidents i {latest_review.format('i')}
                WHERE r.decision IN ('approved', 'edited', 'rejected') GROUP BY 1
                """).fetchall(),
            "reject_reasons": conn.execute(f"""
                SELECT r.reason, count(*) AS total FROM incidents i {latest_review.format('i')}
                WHERE r.decision = 'rejected' GROUP BY 1 ORDER BY 2 DESC
                """).fetchall(),
            "rules": conn.execute(f"""
                SELECT d.rule, count(*) AS total,
                       count(*) FILTER (WHERE r.decision IN ('approved', 'edited', 'rejected')) AS reviewed,
                       count(*) FILTER (WHERE r.decision = 'rejected' AND r.reason = 'false_positive') AS false_positives
                FROM detections d {latest_review.format('d')}
                GROUP BY 1 ORDER BY 2 DESC LIMIT 10
                """).fetchall(),
            "techniques": conn.execute("""
                SELECT unnest(attack) AS technique, count(*) AS total FROM detections
                GROUP BY 1 ORDER BY 2 DESC, 1
                """).fetchall(),
            "times": [row["detected_at"] for row in conn.execute(
                "SELECT detected_at FROM detections WHERE detected_at IS NOT NULL ORDER BY 1").fetchall()],
        }


def load_incident_detail(incident_id):
    with connect() as conn:
        return {
            "events": conn.execute(
                "SELECT * FROM events WHERE incident_id = %s ORDER BY event_time, event_id", (incident_id,)).fetchall(),
            "detections": conn.execute(
                "SELECT detect_id, rule, detected_at, level, priority, attack, raw FROM detections "
                "WHERE incident_id = %s ORDER BY detected_at", (incident_id,)).fetchall(),
            "analyses": conn.execute(
                "SELECT * FROM analyses WHERE incident_id = %s ORDER BY created_at DESC, id DESC", (incident_id,)).fetchall(),
            "reviews": conn.execute(
                "SELECT * FROM reviews WHERE incident_id = %s ORDER BY created_at DESC, id DESC", (incident_id,)).fetchall(),
        }


def load_incidents():
    """Return each incident with its latest analysis, highest score first."""
    with connect() as conn:
        rows = conn.execute("""
            SELECT i.*, a.ai_status, a.verdict, a.confidence, a.severity, a.summary, a.recommended_actions,
                   COALESCE((SELECT array_agg(d.detect_id ORDER BY d.detect_id) FROM detections d
                             WHERE d.incident_id = i.incident_id), '{}') AS detect_ids,
                   (SELECT e.username FROM events e WHERE e.incident_id = i.incident_id AND e.username IS NOT NULL
                    GROUP BY e.username ORDER BY count(*) DESC, e.username LIMIT 1) AS main_user,
                   (SELECT x.summary_after FROM reviews x WHERE x.incident_id = i.incident_id
                    AND x.summary_after IS NOT NULL ORDER BY x.created_at DESC, x.id DESC LIMIT 1) AS edited_summary,
                   r.decision, r.note, r.created_at AS reviewed_at, r.detect_ids AS reviewed_ids
            FROM incidents i
            LEFT JOIN LATERAL (
                SELECT * FROM analyses x WHERE x.incident_id = i.incident_id
                ORDER BY x.created_at DESC, x.id DESC LIMIT 1
            ) a ON true
            LEFT JOIN LATERAL (
                SELECT * FROM reviews x WHERE x.incident_id = i.incident_id
                ORDER BY x.created_at DESC, x.id DESC LIMIT 1
            ) r ON true
            ORDER BY i.score DESC, i.start_time
            """).fetchall()
    return [{
        **_review_status(r),
        "incident_id": r["incident_id"], "host": r["host"], "score": r["score"],
        "start": r["start_time"].strftime("%Y-%m-%dT%H:%M:%SZ"), "end": r["end_time"].strftime("%Y-%m-%dT%H:%M:%SZ"),
        "started_at": r["start_time"], "main_user": r["main_user"] or "",
        "linked_by": r["linked_by"], "context": r["context"], "detect_ids": r["detect_ids"],
        "ai_status": r["ai_status"] or "not analyzed yet",
        "analysis": {"verdict": r["verdict"], "confidence": r["confidence"], "severity": r["severity"],
                     "summary": r["edited_summary"] or r["summary"],
                     "recommended_actions": r["recommended_actions"] or []} if r["verdict"] else {},
    } for r in rows]


if __name__ == "__main__":
    init_db()
    print("tables ready")
