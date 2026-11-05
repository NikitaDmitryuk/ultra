-- Personal opt-in preferences belong to the durable accounting owner.
CREATE TABLE personal_notification_preferences (
 account_id UUID PRIMARY KEY REFERENCES traffic_accounts(account_id),
 credentials BOOLEAN NOT NULL DEFAULT false,
 access BOOLEAN NOT NULL DEFAULT false,
 quota BOOLEAN NOT NULL DEFAULT false,
 availability BOOLEAN NOT NULL DEFAULT false,
 credentials_since TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 access_since TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 quota_since TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 availability_since TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 credential_revision BIGINT NOT NULL DEFAULT 0,
 access_revision BIGINT NOT NULL DEFAULT 0,
 observed JSONB NOT NULL DEFAULT '{}'
);
INSERT INTO personal_notification_preferences(account_id,observed) SELECT account_id,jsonb_build_object('AccessSet',true,'Access',is_active) FROM users;
CREATE TABLE personal_notification_events (
 id BIGSERIAL PRIMARY KEY,
 account_id UUID NOT NULL REFERENCES personal_notification_preferences(account_id),
 category TEXT NOT NULL CHECK(category IN ('credentials','access','quota','availability')),
 kind TEXT NOT NULL,
 revision BIGINT NOT NULL,
 incident BIGINT NOT NULL DEFAULT 0,
 created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
 sent_at TIMESTAMPTZ,
 delivered_to BIGINT,
 terminal BOOLEAN NOT NULL DEFAULT false,
 attempts INTEGER NOT NULL DEFAULT 0,
 lease_until TIMESTAMPTZ,
 next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now(),
 UNIQUE(account_id,category,kind,revision)
);
CREATE INDEX personal_notification_pending ON personal_notification_events(next_attempt_at,id) WHERE sent_at IS NULL AND NOT terminal;
CREATE FUNCTION personal_notification_user_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 INSERT INTO personal_notification_preferences(account_id,observed) VALUES(NEW.account_id,jsonb_build_object('AccessSet',true,'Access',NEW.is_active)) ON CONFLICT DO NOTHING;
 IF TG_OP='UPDATE' AND NEW.is_active IS DISTINCT FROM OLD.is_active THEN
  UPDATE personal_notification_preferences SET access_revision=access_revision+1 WHERE account_id=NEW.account_id;
  -- Capture consent at the desired mutation, not at its potentially late ack.
  INSERT INTO personal_notification_events(account_id,category,kind,revision)
   SELECT account_id,'access',CASE WHEN NEW.is_active THEN 'enabled' ELSE 'disabled' END,access_revision
   FROM personal_notification_preferences WHERE account_id=NEW.account_id AND access
   ON CONFLICT DO NOTHING;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER personal_notification_user_change AFTER INSERT OR UPDATE OF is_active ON users FOR EACH ROW EXECUTE FUNCTION personal_notification_user_change();
