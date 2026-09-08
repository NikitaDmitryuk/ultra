ALTER TABLE users ADD COLUMN enrollment_source TEXT CHECK (enrollment_source IN ('group','invite')),
 ADD COLUMN enrolled_at TIMESTAMPTZ, ADD COLUMN member_pending BOOLEAN NOT NULL DEFAULT false,
 ADD COLUMN member_revision BIGINT NOT NULL DEFAULT 1;
ALTER TABLE subscription_tokens ADD COLUMN encrypted_token BYTEA, ADD COLUMN key_version TEXT;
CREATE TABLE vpn_group (
 singleton BOOLEAN PRIMARY KEY DEFAULT true CHECK (singleton),
 chat_id BIGINT NOT NULL CHECK (chat_id < 0), title TEXT NOT NULL,
 code TEXT NOT NULL, enabled BOOLEAN NOT NULL, updated_by BIGINT NOT NULL
);
CREATE TABLE vpn_invites (
 id BIGSERIAL PRIMARY KEY, token_hash BYTEA NOT NULL UNIQUE,
 recipient BIGINT NOT NULL CHECK (recipient > 0), created_by BIGINT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), expires_at TIMESTAMPTZ NOT NULL,
 used_at TIMESTAMPTZ, cancelled_at TIMESTAMPTZ
);
CREATE TABLE vpn_member_audit (
 id BIGSERIAL PRIMARY KEY, actor BIGINT NOT NULL, member_id BIGINT,
 action TEXT NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE vpn_member_notifications (
 member_id BIGINT NOT NULL, admin_id BIGINT NOT NULL,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), sent_at TIMESTAMPTZ,
 next_attempt TIMESTAMPTZ NOT NULL DEFAULT NOW(), attempts INT NOT NULL DEFAULT 0,
 PRIMARY KEY(member_id, admin_id)
);
CREATE FUNCTION mark_vpn_member_pending() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NEW.enrollment_source IS NOT NULL AND
 (NEW.is_active IS DISTINCT FROM OLD.is_active OR NEW.preferred_exit_id IS DISTINCT FROM OLD.preferred_exit_id) THEN
  NEW.member_pending := true;
  NEW.member_revision := OLD.member_revision + 1;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER vpn_member_pending BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION mark_vpn_member_pending();
