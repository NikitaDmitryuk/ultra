ALTER TABLE traffic_stats ADD COLUMN exit_tag TEXT NOT NULL DEFAULT '';
-- Keep route history when a VM is replaced/deleted; tags are not foreign keys to live nodes.
CREATE TABLE daily_route_traffic (
 user_uuid UUID NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
 day DATE NOT NULL,
 exit_tag TEXT NOT NULL,
 uplink_bytes BIGINT NOT NULL DEFAULT 0,
 downlink_bytes BIGINT NOT NULL DEFAULT 0,
 PRIMARY KEY(user_uuid,day,exit_tag)
);
