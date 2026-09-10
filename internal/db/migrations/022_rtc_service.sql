CREATE TABLE rtc_access (
 user_uuid UUID PRIMARY KEY REFERENCES users(uuid) ON DELETE CASCADE,
 generation UUID NOT NULL,
 room_hash BYTEA UNIQUE,
 encrypted_config BYTEA NOT NULL,
 key_version TEXT NOT NULL,
 enabled BOOLEAN NOT NULL DEFAULT true,
 state TEXT NOT NULL DEFAULT 'preparing',
 error_code TEXT NOT NULL DEFAULT '',
 last_checked_at TIMESTAMPTZ,
 updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE rtc_ingress_hourly (
 user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
 hour TIMESTAMPTZ NOT NULL,
 epoch UUID NOT NULL,
 uplink_bytes BIGINT NOT NULL CHECK (uplink_bytes >= 0),
 downlink_bytes BIGINT NOT NULL CHECK (downlink_bytes >= 0),
 PRIMARY KEY(user_uuid,hour,epoch)
);
CREATE INDEX rtc_ingress_hour ON rtc_ingress_hourly(hour);
CREATE TABLE rtc_key_material (
 singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK(singleton),
 encrypted_key BYTEA NOT NULL,
 key_version TEXT NOT NULL
);
