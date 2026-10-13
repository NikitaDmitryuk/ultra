-- name: EnqueueNotification :exec
INSERT INTO notifications(user_uuid, telegram_id, type, payload, sent_at)
VALUES($1, $2, $3, $4, $5);

-- name: PendingNotifications :many
SELECT *
FROM notifications WHERE sent_at IS NULL ORDER BY created_at LIMIT $1;

-- name: MarkNotificationSent :exec
UPDATE notifications SET sent_at=NOW() WHERE id=$1;

-- name: RecentNotifications :many
SELECT *
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

-- name: ClaimNotifications :many
WITH due AS (
 SELECT id FROM notifications WHERE sent_at IS NULL AND NOT terminal AND next_attempt_at<=NOW() AND (lease_until IS NULL OR lease_until<=NOW()) ORDER BY created_at,id LIMIT $1 FOR UPDATE SKIP LOCKED
)
UPDATE notifications n SET attempts=n.attempts+1,lease_until=NOW()+sqlc.arg(lease)::interval FROM due WHERE n.id=due.id RETURNING n.*;

-- name: CompleteNotification :exec
UPDATE notifications SET sent_at=NOW(),lease_until=NULL,last_error='' WHERE id=$1 AND sent_at IS NULL;

-- name: RetryNotification :exec
UPDATE notifications SET next_attempt_at=$2,last_error=$3,terminal=$4,lease_until=NULL WHERE id=$1 AND sent_at IS NULL;

-- name: CompleteNotificationClaim :execrows
UPDATE notifications SET sent_at=NOW(),lease_until=NULL,last_error=''
WHERE id=$1 AND attempts=$2 AND sent_at IS NULL AND lease_until>NOW();

-- name: RetryNotificationClaim :execrows
UPDATE notifications SET next_attempt_at=$3,last_error=$4,terminal=$5,lease_until=NULL
WHERE id=$1 AND attempts=$2 AND sent_at IS NULL AND lease_until>NOW();
