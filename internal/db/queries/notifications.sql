-- name: EnqueueNotification :exec
INSERT INTO notifications(user_uuid, telegram_id, type, payload, sent_at)
VALUES($1, $2, $3, $4, $5);

-- name: PendingNotifications :many
SELECT id, user_uuid, telegram_id, type, payload, sent_at, created_at
FROM notifications WHERE sent_at IS NULL ORDER BY created_at LIMIT $1;

-- name: MarkNotificationSent :exec
UPDATE notifications SET sent_at=NOW() WHERE id=$1;

-- name: RecentNotifications :many
SELECT id, user_uuid, telegram_id, type, payload, sent_at, created_at
FROM notifications ORDER BY created_at DESC LIMIT $1;

-- name: RecentDistinctNotifications :many
WITH ranked AS (
  SELECT *,
    ROW_NUMBER() OVER (
      PARTITION BY COALESCE(payload->>'dedupe_key', type || ':' || payload::text)
      ORDER BY created_at DESC, id DESC
    ) AS rn
  FROM notifications
)
SELECT id, user_uuid, telegram_id, type, payload, sent_at, created_at
FROM ranked
WHERE rn=1
ORDER BY created_at DESC, id DESC
LIMIT $1;

-- name: GetAlertState :one
SELECT dedupe_key, type, severity, channel, status,
  consecutive_failures, consecutive_successes,
  last_seen_at, last_sent_at, last_payload, updated_at
FROM alert_state
WHERE dedupe_key=$1;

-- name: UpsertAlertState :exec
INSERT INTO alert_state(
  dedupe_key, type, severity, channel, status,
  consecutive_failures, consecutive_successes,
  last_seen_at, last_sent_at, last_payload, updated_at
)
VALUES($1,$2,$3,$4,$5,$6,$7,NOW(),$8,$9,NOW())
ON CONFLICT (dedupe_key) DO UPDATE SET
  type=EXCLUDED.type,
  severity=EXCLUDED.severity,
  channel=EXCLUDED.channel,
  status=EXCLUDED.status,
  consecutive_failures=EXCLUDED.consecutive_failures,
  consecutive_successes=EXCLUDED.consecutive_successes,
  last_seen_at=NOW(),
  last_sent_at=EXCLUDED.last_sent_at,
  last_payload=EXCLUDED.last_payload,
  updated_at=NOW();

-- name: PruneSentNotifications :execrows
DELETE FROM notifications
WHERE sent_at IS NOT NULL AND sent_at < NOW() - INTERVAL '30 days';

-- name: PruneOldIPObservations :execrows
DELETE FROM user_ip_observations
WHERE last_seen_at < NOW() - INTERVAL '30 days';

-- name: PruneOldLeakSignals :execrows
DELETE FROM user_leak_signals
WHERE created_at < NOW() - INTERVAL '30 days';
