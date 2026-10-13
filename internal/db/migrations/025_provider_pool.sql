-- Membership deliberately has no FK to exit_nodes: replacement must retain cost.
CREATE TABLE quota_exit_membership (
 exit_id TEXT PRIMARY KEY,
 scope TEXT NOT NULL CHECK (scope IN ('vultr','manual'))
);
INSERT INTO quota_exit_membership SELECT exit_id::text,source FROM exit_traffic_budgets;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM cloud_operations o JOIN quota_exit_membership m ON m.exit_id=o.body->>'exit_id' WHERE m.scope<>'vultr') THEN
  RAISE EXCEPTION 'conflicting historical quota scope';
 END IF;
END $$;
INSERT INTO quota_exit_membership
 SELECT DISTINCT body->>'exit_id','vultr' FROM cloud_operations
 WHERE COALESCE(body->>'exit_id','')<>''
 ON CONFLICT DO NOTHING;
CREATE FUNCTION remember_quota_exit() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM quota_exit_membership WHERE exit_id=NEW.exit_id::text AND scope<>NEW.source) THEN
  RAISE EXCEPTION 'quota scope is immutable';
 END IF;
 INSERT INTO quota_exit_membership VALUES(NEW.exit_id::text,NEW.source) ON CONFLICT DO NOTHING;
 RETURN NEW;
END $$;
CREATE TRIGGER quota_exit_membership BEFORE INSERT OR UPDATE ON exit_traffic_budgets
 FOR EACH ROW EXECUTE FUNCTION remember_quota_exit();
CREATE TABLE provider_quota_pools (
 scope TEXT NOT NULL CHECK(scope='vultr'),
 period TEXT NOT NULL,
 accrued_bytes BIGINT NOT NULL CHECK(accrued_bytes>=0),
 provider_used_bytes BIGINT NOT NULL CHECK(provider_used_bytes>=0),
 remaining_bytes BIGINT NOT NULL CHECK(remaining_bytes>=0),
 observed_local_bytes BIGINT NOT NULL CHECK(observed_local_bytes>=0),
 observed_at TIMESTAMPTZ NOT NULL,
 provider_error TEXT NOT NULL DEFAULT '',
 PRIMARY KEY(scope,period)
);
