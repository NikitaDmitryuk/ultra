CREATE TABLE exit_traffic_budgets (
 exit_id UUID PRIMARY KEY REFERENCES exit_nodes(id) ON DELETE CASCADE,
 instance_id TEXT NOT NULL DEFAULT '',
 monthly_bytes BIGINT NOT NULL DEFAULT 0 CHECK(monthly_bytes>=0),
 source TEXT NOT NULL CHECK(source IN ('manual','vultr')),
 is_fallback BOOLEAN NOT NULL DEFAULT false,
 provider_used_bytes BIGINT NOT NULL DEFAULT 0,
 account_remaining_bytes BIGINT NOT NULL DEFAULT 0,
 observed_at TIMESTAMPTZ,
 provider_error TEXT NOT NULL DEFAULT '',
 updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE user_exit_quotas (
 user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
 exit_id UUID NOT NULL REFERENCES exit_nodes(id) ON DELETE CASCADE,
 day DATE NOT NULL,
 used_bytes BIGINT NOT NULL,
 limit_bytes BIGINT NOT NULL,
 blocked BOOLEAN NOT NULL,
 applied BOOLEAN NOT NULL DEFAULT false,
 reason TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(user_uuid,exit_id)
);

CREATE UNIQUE INDEX exit_single_fallback ON exit_traffic_budgets(is_fallback) WHERE is_fallback;
