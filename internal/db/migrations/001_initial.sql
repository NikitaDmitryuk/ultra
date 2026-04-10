-- ───── CORE ─────

CREATE TABLE users (
    uuid              UUID        PRIMARY KEY,
    name              TEXT        NOT NULL,
    telegram_id       BIGINT      UNIQUE,
    telegram_username TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    is_active         BOOLEAN     NOT NULL DEFAULT TRUE
);

CREATE TABLE vpn_keys (
    user_uuid     UUID PRIMARY KEY REFERENCES users(uuid) ON DELETE CASCADE,
    vless_uri     TEXT        NOT NULL,
    client_config TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ───── TRAFFIC ─────

CREATE TABLE traffic_stats (
    id             BIGSERIAL   PRIMARY KEY,
    user_uuid      UUID        NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    collected_at   TIMESTAMPTZ NOT NULL,
    uplink_bytes   BIGINT      NOT NULL DEFAULT 0,
    downlink_bytes BIGINT      NOT NULL DEFAULT 0
);
CREATE INDEX traffic_stats_user_time_idx ON traffic_stats(user_uuid, collected_at);

CREATE TABLE monthly_traffic (
    user_uuid      UUID    NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    year           INT     NOT NULL,
    month          INT     NOT NULL,
    uplink_bytes   BIGINT  NOT NULL DEFAULT 0,
    downlink_bytes BIGINT  NOT NULL DEFAULT 0,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_uuid, year, month)
);

-- ───── PLANS & SUBSCRIPTIONS ─────

CREATE TABLE plans (
    id                  SERIAL  PRIMARY KEY,
    name                TEXT    NOT NULL,
    duration_days       INT     NOT NULL,
    traffic_limit_bytes BIGINT,
    price_stars         INT,
    price_ton           NUMERIC(18,9),
    is_active           BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE subscriptions (
    id                  BIGSERIAL   PRIMARY KEY,
    user_uuid           UUID        NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    plan_id             INT         REFERENCES plans(id),
    started_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ,
    traffic_limit_bytes BIGINT,
    is_active           BOOLEAN     NOT NULL DEFAULT TRUE
);
CREATE INDEX subscriptions_user_active_idx ON subscriptions(user_uuid, is_active);

CREATE TABLE payments (
    id                   BIGSERIAL      PRIMARY KEY,
    user_uuid            UUID           REFERENCES users(uuid),
    subscription_id      BIGINT         REFERENCES subscriptions(id),
    amount               NUMERIC(18,9)  NOT NULL,
    currency             TEXT           NOT NULL,
    telegram_charge_id   TEXT           UNIQUE,
    status               TEXT           NOT NULL DEFAULT 'pending',
    created_at           TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

-- ───── TELEGRAM BOT ─────

CREATE TABLE bot_sessions (
    telegram_id BIGINT      PRIMARY KEY,
    state       TEXT,
    data        JSONB       NOT NULL DEFAULT '{}',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE notifications (
    id          BIGSERIAL   PRIMARY KEY,
    user_uuid   UUID        REFERENCES users(uuid),
    telegram_id BIGINT      NOT NULL,
    type        TEXT        NOT NULL,
    payload     JSONB       NOT NULL DEFAULT '{}',
    sent_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX notifications_unsent_idx ON notifications(sent_at) WHERE sent_at IS NULL;
