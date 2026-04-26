CREATE TABLE IF NOT EXISTS admin_audit_log (
    id          BIGSERIAL   PRIMARY KEY,
    telegram_id BIGINT      NOT NULL,
    action      TEXT        NOT NULL,
    target_uuid UUID,
    payload     JSONB       NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS admin_audit_created_idx ON admin_audit_log(created_at DESC);
