CREATE TABLE IF NOT EXISTS user_ip_observations (
    user_uuid     UUID        NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    ip            INET        NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    sessions_seen BIGINT      NOT NULL DEFAULT 1,
    PRIMARY KEY (user_uuid, ip)
);
CREATE INDEX IF NOT EXISTS user_ip_obs_lastseen_idx ON user_ip_observations(last_seen_at DESC);

CREATE TABLE IF NOT EXISTS user_leak_signals (
    id         BIGSERIAL   PRIMARY KEY,
    user_uuid  UUID        NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    kind       TEXT        NOT NULL,
    score      INT         NOT NULL,
    detail     JSONB       NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS user_leak_signals_user_idx ON user_leak_signals(user_uuid, created_at DESC);

ALTER TABLE users ADD COLUMN IF NOT EXISTS leak_policy TEXT NOT NULL DEFAULT 'alert';
ALTER TABLE users ADD COLUMN IF NOT EXISTS leak_max_concurrent_ips INT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS leak_max_unique_ips_24h INT;
