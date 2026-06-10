-- name: UpsertUserIPObservation :exec
INSERT INTO user_ip_observations(user_uuid, ip, first_seen_at, last_seen_at, sessions_seen)
VALUES($1, $2, NOW(), NOW(), 1)
ON CONFLICT (user_uuid, ip) DO UPDATE SET
  last_seen_at=NOW(),
  sessions_seen=user_ip_observations.sessions_seen+1;

-- name: CountConcurrentIPs :one
SELECT COUNT(*)::int FROM user_ip_observations
WHERE user_uuid=$1 AND last_seen_at >= NOW() - $2::interval;

-- name: CountUniqueIPs :one
SELECT COUNT(DISTINCT ip)::int FROM user_ip_observations
WHERE user_uuid=$1 AND last_seen_at >= NOW() - $2::interval;

-- name: InsertLeakSignal :exec
INSERT INTO user_leak_signals(user_uuid, kind, score, detail)
VALUES($1, $2, $3, $4);

-- name: RecentUserLeakSignals :many
SELECT id, user_uuid, kind, score, detail, created_at
FROM user_leak_signals
WHERE user_uuid=$1
ORDER BY created_at DESC
LIMIT $2;

-- name: ConnectionsByBuckets5m :many
SELECT (date_trunc('hour', last_seen_at) + ((extract(minute from last_seen_at)::int / 5) * interval '5 minutes'))::timestamptz AS bucket_start,
  COUNT(DISTINCT ip)::int AS ips
FROM user_ip_observations
WHERE user_uuid=$1 AND last_seen_at >= NOW() - $2::interval
GROUP BY bucket_start
ORDER BY bucket_start;

-- name: ConnectionsByBuckets1h :many
SELECT date_trunc('hour', last_seen_at)::timestamptz AS bucket_start,
  COUNT(DISTINCT ip)::int AS ips
FROM user_ip_observations
WHERE user_uuid=$1 AND last_seen_at >= NOW() - $2::interval
GROUP BY bucket_start
ORDER BY bucket_start;

-- name: ConnectionsByBuckets6h :many
SELECT (date_trunc('day', last_seen_at) + ((extract(hour from last_seen_at)::int / 6) * interval '6 hours'))::timestamptz AS bucket_start,
  COUNT(DISTINCT ip)::int AS ips
FROM user_ip_observations
WHERE user_uuid=$1 AND last_seen_at >= NOW() - $2::interval
GROUP BY bucket_start
ORDER BY bucket_start;

-- name: ConnectionsByBuckets1d :many
SELECT date_trunc('day', last_seen_at)::timestamptz AS bucket_start,
  COUNT(DISTINCT ip)::int AS ips
FROM user_ip_observations
WHERE user_uuid=$1 AND last_seen_at >= NOW() - $2::interval
GROUP BY bucket_start
ORDER BY bucket_start;
