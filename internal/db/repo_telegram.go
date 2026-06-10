package db

import (
	"context"
	"encoding/json"
	"time"
)

// Notification is a queued message to deliver via Telegram.
type Notification struct {
	ID         int64
	UserUUID   *string
	TelegramID int64
	Type       string // e.g. "exit_down", "traffic_spike", "token_leak", "test_alert"
	Payload    map[string]any
	SentAt     *time.Time
	CreatedAt  time.Time
}

// TelegramRepo provides CRUD for the notifications outbox.
type TelegramRepo struct {
	db *DB
}

// NewTelegramRepo creates a TelegramRepo backed by db.
func NewTelegramRepo(db *DB) *TelegramRepo { return &TelegramRepo{db: db} }

// EnqueueNotification adds a notification to the outbox.
func (r *TelegramRepo) EnqueueNotification(ctx context.Context, n Notification) error {
	payloadRaw, err := json.Marshal(n.Payload)
	if err != nil {
		return err
	}
	_, err = r.db.Pool.Exec(ctx,
		`INSERT INTO notifications(user_uuid, telegram_id, type, payload)
		 VALUES($1, $2, $3, $4)`,
		n.UserUUID, n.TelegramID, n.Type, payloadRaw,
	)
	return err
}

// PendingNotifications returns up to limit unsent notifications ordered by creation time.
func (r *TelegramRepo) PendingNotifications(ctx context.Context, limit int) ([]Notification, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT id, user_uuid, telegram_id, type, payload, created_at
		 FROM notifications WHERE sent_at IS NULL ORDER BY created_at LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		var payloadRaw []byte
		if err := rows.Scan(&n.ID, &n.UserUUID, &n.TelegramID, &n.Type, &payloadRaw, &n.CreatedAt); err != nil {
			return nil, err
		}
		if len(payloadRaw) > 0 {
			_ = json.Unmarshal(payloadRaw, &n.Payload)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// MarkNotificationSent stamps sent_at=NOW() on a delivered notification.
func (r *TelegramRepo) MarkNotificationSent(ctx context.Context, id int64) error {
	_, err := r.db.Pool.Exec(ctx,
		"UPDATE notifications SET sent_at=NOW() WHERE id=$1", id,
	)
	return err
}

// RecentNotifications returns last notifications regardless of sent status.
func (r *TelegramRepo) RecentNotifications(ctx context.Context, limit int) ([]Notification, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT id, user_uuid, telegram_id, type, payload, sent_at, created_at
		 FROM notifications ORDER BY created_at DESC LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		var payloadRaw []byte
		if err := rows.Scan(&n.ID, &n.UserUUID, &n.TelegramID, &n.Type, &payloadRaw, &n.SentAt, &n.CreatedAt); err != nil {
			return nil, err
		}
		if len(payloadRaw) > 0 {
			_ = json.Unmarshal(payloadRaw, &n.Payload)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// RecentDistinctNotifications returns recent unique notification events grouped by
// type and payload. Telegram fan-out creates one notification per admin; this
// view is intended for compact UI timelines.
func (r *TelegramRepo) RecentDistinctNotifications(ctx context.Context, limit int) ([]Notification, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT MAX(id) AS id,
		        MIN(telegram_id) AS telegram_id,
		        type,
		        payload,
		        MAX(sent_at) AS sent_at,
		        MAX(created_at) AS created_at
		 FROM notifications
		 GROUP BY type, payload
		 ORDER BY MAX(created_at) DESC
		 LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		var payloadRaw []byte
		if err := rows.Scan(&n.ID, &n.TelegramID, &n.Type, &payloadRaw, &n.SentAt, &n.CreatedAt); err != nil {
			return nil, err
		}
		if len(payloadRaw) > 0 {
			_ = json.Unmarshal(payloadRaw, &n.Payload)
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// HasRecentNotification reports whether a matching notification was enqueued
// recently. payloadContains is matched as JSONB containment, so callers can
// dedupe by stable fields such as user_uuid, exit_id, kind, from, or to.
func (r *TelegramRepo) HasRecentNotification(
	ctx context.Context,
	typ string,
	payloadContains map[string]any,
	within time.Duration,
) (bool, error) {
	raw, err := json.Marshal(payloadContains)
	if err != nil {
		return false, err
	}
	var exists bool
	err = r.db.Pool.QueryRow(ctx,
		`SELECT EXISTS (
		   SELECT 1
		   FROM notifications
		   WHERE type=$1
		     AND payload @> $2::jsonb
		     AND created_at >= NOW() - $3::interval
		 )`,
		typ, raw, intervalSQL(within),
	).Scan(&exists)
	return exists, err
}

// PruneMonitoringRetention deletes old monitoring rows to keep the DB small on VPS.
// - notifications: sent rows older than 30 days
// - user_ip_observations: rows with last_seen_at older than 30 days
// - user_leak_signals: rows with created_at older than 30 days
func (r *TelegramRepo) PruneMonitoringRetention(ctx context.Context) (notif, obs, sig int64, err error) {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	tag, err := tx.Exec(ctx, `
		DELETE FROM notifications
		WHERE sent_at IS NOT NULL AND sent_at < NOW() - INTERVAL '30 days'
	`)
	if err != nil {
		return 0, 0, 0, err
	}
	notif = tag.RowsAffected()

	tag, err = tx.Exec(ctx, `
		DELETE FROM user_ip_observations
		WHERE last_seen_at < NOW() - INTERVAL '30 days'
	`)
	if err != nil {
		return 0, 0, 0, err
	}
	obs = tag.RowsAffected()

	tag, err = tx.Exec(ctx, `
		DELETE FROM user_leak_signals
		WHERE created_at < NOW() - INTERVAL '30 days'
	`)
	if err != nil {
		return 0, 0, 0, err
	}
	sig = tag.RowsAffected()

	if err := tx.Commit(ctx); err != nil {
		return 0, 0, 0, err
	}
	return notif, obs, sig, nil
}
