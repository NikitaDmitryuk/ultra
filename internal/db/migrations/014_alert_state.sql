CREATE TABLE IF NOT EXISTS alert_state (
    dedupe_key              TEXT        PRIMARY KEY,
    type                    TEXT        NOT NULL,
    severity                TEXT        NOT NULL,
    channel                 TEXT        NOT NULL,
    status                  TEXT        NOT NULL DEFAULT 'open',
    consecutive_failures    INT         NOT NULL DEFAULT 0,
    consecutive_successes   INT         NOT NULL DEFAULT 0,
    last_seen_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_sent_at            TIMESTAMPTZ,
    last_payload            JSONB       NOT NULL DEFAULT '{}',
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS alert_state_updated_idx ON alert_state(updated_at DESC);
