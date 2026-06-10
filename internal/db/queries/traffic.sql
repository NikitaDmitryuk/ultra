-- name: InsertTrafficSample :exec
INSERT INTO traffic_stats(user_uuid, collected_at, uplink_bytes, downlink_bytes)
VALUES($1, $2, $3, $4);

-- name: UpsertMonthlyTraffic :exec
INSERT INTO monthly_traffic(user_uuid, year, month, uplink_bytes, downlink_bytes, updated_at)
VALUES($1, $2, $3, $4, $5, NOW())
ON CONFLICT(user_uuid, year, month) DO UPDATE SET
  uplink_bytes = monthly_traffic.uplink_bytes + EXCLUDED.uplink_bytes,
  downlink_bytes = monthly_traffic.downlink_bytes + EXCLUDED.downlink_bytes,
  updated_at = NOW();

-- name: GetMonthlyAll :many
SELECT user_uuid, year, month, uplink_bytes, downlink_bytes
FROM monthly_traffic WHERE year=$1 AND month=$2 ORDER BY user_uuid;

-- name: GetMonthlyUser :one
SELECT user_uuid, year, month, uplink_bytes, downlink_bytes
FROM monthly_traffic WHERE user_uuid=$1 AND year=$2 AND month=$3;

-- name: GetMonthlyHistory :many
SELECT year, month,
  SUM(uplink_bytes)::bigint AS uplink_bytes,
  SUM(downlink_bytes)::bigint AS downlink_bytes
FROM monthly_traffic
GROUP BY year, month
ORDER BY year DESC, month DESC
LIMIT $1;

-- name: PruneOldTrafficSamples :execrows
DELETE FROM traffic_stats WHERE collected_at < $1;

-- name: GetLastSeenAll :many
SELECT user_uuid, MAX(collected_at)::timestamptz AS last_seen
FROM traffic_stats
WHERE uplink_bytes + downlink_bytes > 0
GROUP BY user_uuid;

-- name: TrafficTimeline5m :many
SELECT (date_trunc('hour', collected_at) + ((extract(minute from collected_at)::int / 5) * interval '5 minutes'))::timestamptz AS bucket_start,
  COALESCE(SUM(uplink_bytes), 0)::bigint AS uplink_bytes,
  COALESCE(SUM(downlink_bytes), 0)::bigint AS downlink_bytes
FROM traffic_stats
WHERE user_uuid=$1 AND collected_at >= NOW() - $2::interval
GROUP BY bucket_start
ORDER BY bucket_start;

-- name: TrafficTimeline1h :many
SELECT date_trunc('hour', collected_at)::timestamptz AS bucket_start,
  COALESCE(SUM(uplink_bytes), 0)::bigint AS uplink_bytes,
  COALESCE(SUM(downlink_bytes), 0)::bigint AS downlink_bytes
FROM traffic_stats
WHERE user_uuid=$1 AND collected_at >= NOW() - $2::interval
GROUP BY bucket_start
ORDER BY bucket_start;

-- name: TrafficTimeline6h :many
SELECT (date_trunc('day', collected_at) + ((extract(hour from collected_at)::int / 6) * interval '6 hours'))::timestamptz AS bucket_start,
  COALESCE(SUM(uplink_bytes), 0)::bigint AS uplink_bytes,
  COALESCE(SUM(downlink_bytes), 0)::bigint AS downlink_bytes
FROM traffic_stats
WHERE user_uuid=$1 AND collected_at >= NOW() - $2::interval
GROUP BY bucket_start
ORDER BY bucket_start;

-- name: TrafficTimeline1d :many
SELECT date_trunc('day', collected_at)::timestamptz AS bucket_start,
  COALESCE(SUM(uplink_bytes), 0)::bigint AS uplink_bytes,
  COALESCE(SUM(downlink_bytes), 0)::bigint AS downlink_bytes
FROM traffic_stats
WHERE user_uuid=$1 AND collected_at >= NOW() - $2::interval
GROUP BY bucket_start
ORDER BY bucket_start;
