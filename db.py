"""PostgreSQL storage for Vigil. Run `python db.py` to create the tables."""
import os, pathlib
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from adapters.limacharlie import _normalize_time, _parse_attack_techniques

BASE = pathlib.Path(__file__).parent


def connect():
    return psycopg.connect(host="localhost", port=5432, dbname="vigil", user="vigil",
                           password=os.environ["VIGIL_DB_PASSWORD"], row_factory=dict_row)


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
            INSERT INTO analyses (incident_id, detect_ids, model, ai_status, verdict, confidence, summary,
                                  claims, recommended_actions, errors)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (record["incident_id"], record["detect_ids"], record.get("model"), record["ai_status"],
                  analysis.get("verdict"), analysis.get("confidence"), analysis.get("summary"),
                  Jsonb(analysis.get("claims", [])), Jsonb(analysis.get("recommended_actions", [])),
                  Jsonb(record.get("errors", []))))


def load_incidents():
    """Return each incident with its latest analysis, highest score first."""
    with connect() as conn:
        rows = conn.execute("""
            SELECT i.*, a.ai_status, a.verdict, a.confidence, a.summary, a.recommended_actions,
                   COALESCE((SELECT array_agg(d.detect_id ORDER BY d.detect_id) FROM detections d
                             WHERE d.incident_id = i.incident_id), '{}') AS detect_ids
            FROM incidents i
            LEFT JOIN LATERAL (
                SELECT * FROM analyses x WHERE x.incident_id = i.incident_id
                ORDER BY x.created_at DESC, x.id DESC LIMIT 1
            ) a ON true
            ORDER BY i.score DESC, i.start_time
            """).fetchall()
    return [{
        "incident_id": r["incident_id"], "host": r["host"], "score": r["score"],
        "start": r["start_time"].strftime("%Y-%m-%dT%H:%M:%SZ"), "end": r["end_time"].strftime("%Y-%m-%dT%H:%M:%SZ"),
        "linked_by": r["linked_by"], "context": r["context"], "detect_ids": r["detect_ids"],
        "ai_status": r["ai_status"] or "not analyzed yet",
        "analysis": {"verdict": r["verdict"], "confidence": r["confidence"], "summary": r["summary"],
                     "recommended_actions": r["recommended_actions"] or []} if r["verdict"] else {},
    } for r in rows]


if __name__ == "__main__":
    init_db()
    print("tables ready")
