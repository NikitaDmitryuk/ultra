CREATE TABLE cloud_offers (
 id UUID PRIMARY KEY, actor BIGINT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, body JSONB NOT NULL
);
CREATE TABLE cloud_operations (
 id UUID PRIMARY KEY REFERENCES cloud_offers(id),
 state TEXT NOT NULL, body JSONB NOT NULL, occupies_slot BOOLEAN NOT NULL DEFAULT true,
 created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE vpn_locations (
 id UUID PRIMARY KEY, provider_region TEXT UNIQUE, name TEXT NOT NULL,
 exit_id UUID REFERENCES exit_nodes(id) ON DELETE SET NULL, published BOOLEAN NOT NULL DEFAULT false, applied BOOLEAN NOT NULL DEFAULT false
);
CREATE TABLE vpn_route_credentials (
 uuid UUID PRIMARY KEY, user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
 location_id UUID NOT NULL REFERENCES vpn_locations(id), UNIQUE(user_uuid,location_id)
);
INSERT INTO vpn_locations(id,name,exit_id,published,applied)
 SELECT id,COALESCE(NULLIF(display_name,''),NULLIF(city,''),name),id,true,true FROM exit_nodes WHERE enabled;
INSERT INTO vpn_route_credentials(uuid,user_uuid,location_id)
 SELECT gen_random_uuid(),u.uuid,l.id FROM users u CROSS JOIN vpn_locations l WHERE u.kind='vless' AND l.published;
CREATE FUNCTION create_vpn_route_credentials() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(817365007);
 IF NEW.kind='vless' THEN
  INSERT INTO vpn_route_credentials(uuid,user_uuid,location_id)
   SELECT gen_random_uuid(),NEW.uuid,id FROM vpn_locations WHERE published ON CONFLICT DO NOTHING;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER vpn_user_route_credentials AFTER INSERT ON users FOR EACH ROW EXECUTE FUNCTION create_vpn_route_credentials();
CREATE TABLE cloud_audit(id BIGSERIAL PRIMARY KEY,actor BIGINT NOT NULL,operation_id UUID NOT NULL,action TEXT NOT NULL,created_at TIMESTAMPTZ NOT NULL DEFAULT NOW());
CREATE TABLE node_replication (
 node_id UUID PRIMARY KEY REFERENCES exit_nodes(id) ON DELETE CASCADE,
 state TEXT NOT NULL, free_bytes BIGINT NOT NULL DEFAULT 0, required_bytes BIGINT NOT NULL DEFAULT 0,
 detail TEXT NOT NULL DEFAULT '', checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE cloud_operation_events (
 id BIGSERIAL PRIMARY KEY, operation_id UUID NOT NULL REFERENCES cloud_operations(id),
 phase TEXT NOT NULL, outcome TEXT NOT NULL, code TEXT NOT NULL DEFAULT '', http_status INT NOT NULL DEFAULT 0,
 duration_ms BIGINT NOT NULL DEFAULT 0, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX cloud_operation_events_lookup ON cloud_operation_events(operation_id,id);
