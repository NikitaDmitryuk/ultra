-- name: UserSocksPortExists :one
SELECT EXISTS(SELECT 1 FROM users WHERE socks_port=$1);

-- name: InsertVlessUser :exec
INSERT INTO users(uuid, name, kind) VALUES($1, $2, 'vless');

-- name: InsertSocksUser :exec
INSERT INTO users(uuid, name, kind, socks_username, socks_password, socks_port)
VALUES($1, $2, 'socks5', $3, $4, $5);

-- name: RotateSocksPassword :one
UPDATE users SET socks_password=$1 WHERE uuid=$2 AND kind='socks5' AND is_active=true
RETURNING uuid, name, kind, is_active, disabled_at,
  socks_username, socks_password, socks_port,
  leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h,
  preferred_exit_id;

-- name: RenameUser :one
UPDATE users SET name=$1 WHERE uuid=$2
RETURNING uuid, name, kind, is_active, disabled_at,
  socks_username, socks_password, socks_port,
  leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h,
  preferred_exit_id;

-- name: DisableUser :execrows
UPDATE users SET is_active=false, disabled_at=NOW() WHERE uuid=$1 AND is_active=true;

-- name: DeleteUser :execrows
DELETE FROM users WHERE uuid=$1;

-- name: EnableUser :execrows
UPDATE users SET is_active=true, disabled_at=NULL WHERE uuid=$1;

-- name: CloneUserForUUIDRotation :exec
INSERT INTO users(
  uuid, name, telegram_id, telegram_username, created_at, is_active, disabled_at,
  leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h,
  kind, socks_username, socks_password, socks_port, preferred_exit_id
)
SELECT
  $2, u.name, u.telegram_id, u.telegram_username, u.created_at, u.is_active, u.disabled_at,
  u.leak_policy, u.leak_max_concurrent_ips, u.leak_max_unique_ips_24h,
  u.kind, u.socks_username, u.socks_password, u.socks_port, u.preferred_exit_id
FROM users u WHERE u.uuid=$1;

-- name: MoveTrafficStatsUserUUID :exec
UPDATE traffic_stats SET user_uuid=$2 WHERE user_uuid=$1;

-- name: MoveMonthlyTrafficUserUUID :exec
UPDATE monthly_traffic SET user_uuid=$2 WHERE user_uuid=$1;

-- name: MoveNotificationsUserUUID :exec
UPDATE notifications SET user_uuid=$2 WHERE user_uuid=$1;

-- name: MoveIPObservationsUserUUID :exec
UPDATE user_ip_observations SET user_uuid=$2 WHERE user_uuid=$1;

-- name: MoveLeakSignalsUserUUID :exec
UPDATE user_leak_signals SET user_uuid=$2 WHERE user_uuid=$1;

-- name: ListActiveUsers :many
SELECT uuid, name, kind, is_active, disabled_at,
  socks_username, socks_password, socks_port,
  leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h,
  preferred_exit_id
FROM users WHERE is_active=true ORDER BY created_at;

-- name: ListAllUsers :many
SELECT uuid, name, kind, is_active, disabled_at,
  socks_username, socks_password, socks_port,
  leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h,
  preferred_exit_id
FROM users ORDER BY created_at;

-- name: GetUser :one
SELECT uuid, name, kind, is_active, disabled_at,
  socks_username, socks_password, socks_port,
  leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h,
  preferred_exit_id
FROM users WHERE uuid=$1;

-- name: SetUserPreferredExit :one
UPDATE users SET preferred_exit_id=$2 WHERE uuid=$1 AND is_active=true
RETURNING uuid, name, kind, is_active, disabled_at,
  socks_username, socks_password, socks_port,
  leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h,
  preferred_exit_id;
