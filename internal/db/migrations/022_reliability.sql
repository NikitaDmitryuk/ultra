-- Durable accounting identity is independent of revocable VPN credentials.
CREATE TABLE traffic_accounts(account_id UUID PRIMARY KEY DEFAULT gen_random_uuid());
ALTER TABLE users ADD COLUMN account_id UUID;
UPDATE users SET account_id=uuid;
INSERT INTO traffic_accounts SELECT account_id FROM users;
ALTER TABLE users ALTER COLUMN account_id SET DEFAULT gen_random_uuid();
ALTER TABLE users ALTER COLUMN account_id SET NOT NULL;
ALTER TABLE users ADD CONSTRAINT users_account_unique UNIQUE(account_id) DEFERRABLE INITIALLY DEFERRED;
CREATE FUNCTION ensure_traffic_account() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN INSERT INTO traffic_accounts(account_id) VALUES(NEW.account_id) ON CONFLICT DO NOTHING; RETURN NEW; END $$;
CREATE TRIGGER users_traffic_account BEFORE INSERT ON users FOR EACH ROW EXECUTE FUNCTION ensure_traffic_account();
ALTER TABLE users ADD FOREIGN KEY(account_id) REFERENCES traffic_accounts(account_id);
CREATE FUNCTION forbid_account_rotation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN IF NEW.account_id IS DISTINCT FROM OLD.account_id THEN RAISE EXCEPTION 'accounting identity is immutable'; END IF; RETURN NEW; END $$;
CREATE TRIGGER users_immutable_account BEFORE UPDATE OF account_id ON users FOR EACH ROW EXECUTE FUNCTION forbid_account_rotation();
CREATE TABLE traffic_batches(node_id UUID NOT NULL,batch_id UUID NOT NULL,digest BYTEA NOT NULL,committed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),PRIMARY KEY(node_id,batch_id));
-- No FK to users or exit_nodes: deletion must not return consumed capacity.
CREATE TABLE account_exit_usage(account_id UUID NOT NULL REFERENCES traffic_accounts(account_id),exit_id TEXT NOT NULL,period TEXT NOT NULL,uplink_bytes BIGINT NOT NULL DEFAULT 0,downlink_bytes BIGINT NOT NULL DEFAULT 0,charged_bytes BIGINT NOT NULL DEFAULT 0,PRIMARY KEY(account_id,exit_id,period));
INSERT INTO account_exit_usage(account_id,exit_id,period,uplink_bytes,downlink_bytes)
 SELECT u.account_id, CASE WHEN t.exit_tag LIKE 'to-exit-%' THEN substring(t.exit_tag FROM 9) ELSE t.exit_tag END,to_char(t.day,'YYYY-MM'),SUM(t.uplink_bytes),SUM(t.downlink_bytes)
 FROM daily_route_traffic t JOIN users u ON u.uuid=t.user_uuid GROUP BY u.account_id,t.exit_tag,to_char(t.day,'YYYY-MM');
ALTER TABLE notifications ADD COLUMN attempts INT NOT NULL DEFAULT 0,ADD COLUMN next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),ADD COLUMN lease_until TIMESTAMPTZ,ADD COLUMN last_error TEXT NOT NULL DEFAULT '',ADD COLUMN terminal BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX notifications_due ON notifications(next_attempt_at) WHERE sent_at IS NULL AND NOT terminal;
CREATE TABLE recovery_heartbeat(singleton BOOLEAN PRIMARY KEY CHECK(singleton),observed_at TIMESTAMPTZ NOT NULL);
ALTER TABLE exit_traffic_budgets ADD COLUMN emergency_started_at TIMESTAMPTZ, ADD COLUMN emergency_baseline_bytes BIGINT, ADD COLUMN provider_observed_local_bytes BIGINT NOT NULL DEFAULT 0;

ALTER TABLE vpn_member_notifications ADD COLUMN terminal BOOLEAN NOT NULL DEFAULT false, ADD COLUMN last_error TEXT NOT NULL DEFAULT '', ADD COLUMN lease_until TIMESTAMPTZ;
