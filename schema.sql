CREATE TABLE IF NOT EXISTS incidents (
    incident_id text PRIMARY KEY,
    host        text NOT NULL,
    score       integer NOT NULL,
    start_time  timestamptz NOT NULL,
    end_time    timestamptz NOT NULL,
    linked_by   text[] NOT NULL DEFAULT '{}',
    context     jsonb NOT NULL DEFAULT '{}',
    updated_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS detections (
    detect_id   text PRIMARY KEY,
    incident_id text REFERENCES incidents ON DELETE SET NULL,
    rule        text,
    host        text,
    detected_at timestamptz,
    priority    integer,
    level       text,
    attack      text[] NOT NULL DEFAULT '{}',
    raw         jsonb NOT NULL
);
CREATE INDEX IF NOT EXISTS detections_incident_idx ON detections (incident_id);
CREATE INDEX IF NOT EXISTS detections_time_idx ON detections (detected_at);

CREATE TABLE IF NOT EXISTS events (
    incident_id    text NOT NULL REFERENCES incidents ON DELETE CASCADE,
    event_id       text NOT NULL,
    event_time     timestamptz,
    event_type     text,
    process        text,
    parent         text,
    command_line   text,
    username       text,
    target_process text,
    access_flags   bigint,
    PRIMARY KEY (incident_id, event_id)
);

CREATE TABLE IF NOT EXISTS analyses (
    id                  bigserial PRIMARY KEY,
    incident_id         text NOT NULL REFERENCES incidents ON DELETE CASCADE,
    detect_ids          text[] NOT NULL,
    model               text,
    ai_status           text NOT NULL,
    verdict             text,
    confidence          text,
    summary             text,
    claims              jsonb NOT NULL DEFAULT '[]',
    recommended_actions jsonb NOT NULL DEFAULT '[]',
    errors              jsonb NOT NULL DEFAULT '[]',
    created_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS analyses_incident_idx ON analyses (incident_id, created_at DESC);

ALTER TABLE analyses ADD COLUMN IF NOT EXISTS severity text;
ALTER TABLE analyses ADD COLUMN IF NOT EXISTS attack_chain jsonb NOT NULL DEFAULT '[]';
ALTER TABLE analyses ADD COLUMN IF NOT EXISTS playbooks text[] NOT NULL DEFAULT '{}';
ALTER TABLE analyses ADD COLUMN IF NOT EXISTS iocs jsonb NOT NULL DEFAULT '[]';
ALTER TABLE analyses ADD COLUMN IF NOT EXISTS evidence_requests jsonb NOT NULL DEFAULT '[]';

-- No foreign key: analyst decisions must survive if detections are regrouped.
CREATE TABLE IF NOT EXISTS reviews (
    id          bigserial PRIMARY KEY,
    incident_id text NOT NULL,
    decision    text NOT NULL CHECK (decision IN ('approved', 'rejected', 'closed', 'reopened')),
    note        text NOT NULL DEFAULT '',
    detect_ids  text[] NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS reviews_incident_idx ON reviews (incident_id, created_at DESC);
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS reason text NOT NULL DEFAULT '';
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS summary_before text;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS summary_after text;
ALTER TABLE reviews DROP CONSTRAINT IF EXISTS reviews_decision_check;
ALTER TABLE reviews ADD CONSTRAINT reviews_decision_check
    CHECK (decision IN ('in_review', 'approved', 'edited', 'rejected', 'closed', 'reopened'));
