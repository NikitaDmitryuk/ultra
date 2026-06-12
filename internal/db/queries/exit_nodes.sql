-- name: ListExitNodes :many
SELECT id, name, address, port, tunnel_uuid, pinned_peer_cert_sha256,
  country_code, country_name, city, display_name,
  priority, enabled, created_at, updated_at
FROM exit_nodes ORDER BY priority ASC, created_at ASC;

-- name: GetExitNode :one
SELECT id, name, address, port, tunnel_uuid, pinned_peer_cert_sha256,
  country_code, country_name, city, display_name,
  priority, enabled, created_at, updated_at
FROM exit_nodes WHERE id=$1;

-- name: CountEnabledExitNodes :one
SELECT COUNT(*)::int FROM exit_nodes WHERE enabled=TRUE;

-- name: FindExitNodeByAddressPort :one
SELECT id FROM exit_nodes WHERE address=$1 AND port=$2;

-- name: FindExitNodeByTunnelUUID :one
SELECT id FROM exit_nodes WHERE tunnel_uuid=$1;

-- name: MergeExitByAddressPort :exec
UPDATE exit_nodes SET
  name=$2,
  tunnel_uuid=CASE WHEN $3<>'' THEN $3 ELSE tunnel_uuid END,
  pinned_peer_cert_sha256=CASE WHEN $4<>'' THEN $4 ELSE pinned_peer_cert_sha256 END,
  country_code=CASE WHEN $5<>'' THEN $5 ELSE country_code END,
  country_name=CASE WHEN $6<>'' THEN $6 ELSE country_name END,
  city=CASE WHEN $7<>'' THEN $7 ELSE city END,
  display_name=CASE WHEN $8<>'' THEN $8 ELSE display_name END,
  priority=CASE WHEN $9>0 THEN $9 ELSE priority END,
  enabled=$10,
  updated_at=$11
WHERE id=$1;

-- name: MergeExitByTunnelUUID :exec
UPDATE exit_nodes SET
  name=$2,
  pinned_peer_cert_sha256=CASE WHEN $3<>'' THEN $3 ELSE pinned_peer_cert_sha256 END,
  country_code=CASE WHEN $4<>'' THEN $4 ELSE country_code END,
  country_name=CASE WHEN $5<>'' THEN $5 ELSE country_name END,
  city=CASE WHEN $6<>'' THEN $6 ELSE city END,
  display_name=CASE WHEN $7<>'' THEN $7 ELSE display_name END,
  priority=CASE WHEN $8>0 THEN $8 ELSE priority END,
  enabled=$9,
  updated_at=$10
WHERE id=$1;

-- name: CountExitNodesByTunnelUUID :one
SELECT COUNT(*)::int FROM exit_nodes WHERE tunnel_uuid=$1;

-- name: CountEnabledExitNodesByAddressPort :one
SELECT COUNT(*)::int FROM exit_nodes WHERE enabled=TRUE AND address=$1 AND port=$2;

-- name: InsertExitNode :one
INSERT INTO exit_nodes(
  id, name, address, port, tunnel_uuid, pinned_peer_cert_sha256,
  country_code, country_name, city, display_name,
  priority, enabled
)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
RETURNING id, name, address, port, tunnel_uuid, pinned_peer_cert_sha256,
  country_code, country_name, city, display_name,
  priority, enabled, created_at, updated_at;

-- name: CountEnabledExitNodeDuplicate :one
SELECT COUNT(*)::int FROM exit_nodes WHERE enabled=TRUE AND address=$1 AND port=$2 AND id<>$3;

-- name: UpdateExitNode :one
UPDATE exit_nodes SET
  name=$2,
  address=$3,
  port=$4,
  country_code=$5,
  country_name=$6,
  city=$7,
  display_name=$8,
  priority=$9,
  enabled=$10,
  updated_at=$11
WHERE id=$1
RETURNING id, name, address, port, tunnel_uuid, pinned_peer_cert_sha256,
  country_code, country_name, city, display_name,
  priority, enabled, created_at, updated_at;

-- name: DeleteExitNode :execrows
DELETE FROM exit_nodes WHERE id=$1;
