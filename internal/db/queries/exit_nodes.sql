-- name: ListExitNodes :many
SELECT id, name, address, port, tunnel_uuid, pinned_peer_cert_sha256, priority, enabled, created_at, updated_at
FROM exit_nodes ORDER BY priority ASC, created_at ASC;

-- name: GetExitNode :one
SELECT id, name, address, port, tunnel_uuid, pinned_peer_cert_sha256, priority, enabled, created_at, updated_at
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
  priority=CASE WHEN $5>0 THEN $5 ELSE priority END,
  enabled=$6,
  updated_at=$7
WHERE id=$1;

-- name: MergeExitByTunnelUUID :exec
UPDATE exit_nodes SET
  name=$2,
  pinned_peer_cert_sha256=CASE WHEN $3<>'' THEN $3 ELSE pinned_peer_cert_sha256 END,
  priority=CASE WHEN $4>0 THEN $4 ELSE priority END,
  enabled=$5,
  updated_at=$6
WHERE id=$1;

-- name: CountExitNodesByTunnelUUID :one
SELECT COUNT(*)::int FROM exit_nodes WHERE tunnel_uuid=$1;

-- name: CountEnabledExitNodesByAddressPort :one
SELECT COUNT(*)::int FROM exit_nodes WHERE enabled=TRUE AND address=$1 AND port=$2;

-- name: InsertExitNode :one
INSERT INTO exit_nodes(id, name, address, port, tunnel_uuid, pinned_peer_cert_sha256, priority, enabled)
VALUES($1,$2,$3,$4,$5,$6,$7,$8)
RETURNING id, name, address, port, tunnel_uuid, pinned_peer_cert_sha256, priority, enabled, created_at, updated_at;

-- name: CountEnabledExitNodeDuplicate :one
SELECT COUNT(*)::int FROM exit_nodes WHERE enabled=TRUE AND address=$1 AND port=$2 AND id<>$3;

-- name: UpdateExitNode :one
UPDATE exit_nodes SET name=$2, address=$3, port=$4, priority=$5, enabled=$6, updated_at=$7
WHERE id=$1
RETURNING id, name, address, port, tunnel_uuid, pinned_peer_cert_sha256, priority, enabled, created_at, updated_at;

-- name: DeleteExitNode :execrows
DELETE FROM exit_nodes WHERE id=$1;
