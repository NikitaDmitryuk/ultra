-- ───── BOT ADMINISTRATION ─────

CREATE TABLE bot_admins (
    telegram_id   BIGINT      PRIMARY KEY,
    telegram_name TEXT        NOT NULL DEFAULT '',
    added_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE bot_invite_tokens (
    token      TEXT        PRIMARY KEY,
    used_by    BIGINT      REFERENCES bot_admins(telegram_id),
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
