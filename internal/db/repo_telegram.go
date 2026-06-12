package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
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

type AlertState struct {
	DedupeKey            string
	Type                 string
	Severity             string
	Channel              string
	Status               string
	ConsecutiveFailures  int
	ConsecutiveSuccesses int
	LastSeenAt           time.Time
	LastSentAt           *time.Time
	LastPayload          map[string]any
	UpdatedAt            time.Time
}

// TelegramRepo provides CRUD for the notifications outbox.
type TelegramRepo struct {
	db *DB
}

// NewTelegramRepo creates a TelegramRepo backed by db.
func NewTelegramRepo(db *DB) *TelegramRepo { return &TelegramRepo{db: db} }

func notificationFromFields(
	id int64,
	userUUID pgtype.UUID,
	telegramID int64,
	typ string,
	payload []byte,
	sentAt, createdAt pgtype.Timestamptz,
) Notification {
	n := Notification{
		ID:         id,
		UserUUID:   ptrFromPGUUID(userUUID),
		TelegramID: telegramID,
		Type:       typ,
		SentAt:     ptrFromPGTime(sentAt),
		CreatedAt:  timeFromPG(createdAt),
	}
	if len(payload) > 0 {
		_ = json.Unmarshal(payload, &n.Payload)
	}
	return n
}

func notificationFromSQLC(row sqlc.Notification) Notification {
	return notificationFromFields(row.ID, row.UserUuid, row.TelegramID, row.Type, row.Payload, row.SentAt, row.CreatedAt)
}

func notificationFromDistinctSQLC(row sqlc.RecentDistinctNotificationsRow) Notification {
	return notificationFromFields(row.ID, row.UserUuid, row.TelegramID, row.Type, row.Payload, row.SentAt, row.CreatedAt)
}

func alertStateFromSQLC(row sqlc.AlertState) AlertState {
	s := AlertState{
		DedupeKey:            row.DedupeKey,
		Type:                 row.Type,
		Severity:             row.Severity,
		Channel:              row.Channel,
		Status:               row.Status,
		ConsecutiveFailures:  int(row.ConsecutiveFailures),
		ConsecutiveSuccesses: int(row.ConsecutiveSuccesses),
		LastSeenAt:           timeFromPG(row.LastSeenAt),
		LastSentAt:           ptrFromPGTime(row.LastSentAt),
		UpdatedAt:            timeFromPG(row.UpdatedAt),
	}
	if len(row.LastPayload) > 0 {
		_ = json.Unmarshal(row.LastPayload, &s.LastPayload)
	}
	return s
}

// EnqueueNotification adds a notification to the outbox.
func (r *TelegramRepo) EnqueueNotification(ctx context.Context, n Notification) error {
	payloadRaw, err := json.Marshal(n.Payload)
	if err != nil {
		return err
	}
	userUUID, err := toPGUUIDPtr(n.UserUUID)
	if err != nil {
		return err
	}
	return r.db.Queries.EnqueueNotification(ctx, sqlc.EnqueueNotificationParams{
		UserUuid:   userUUID,
		TelegramID: n.TelegramID,
		Type:       n.Type,
		Payload:    payloadRaw,
		SentAt:     toPGTimePtr(n.SentAt),
	})
}

// PendingNotifications returns up to limit unsent notifications ordered by creation time.
func (r *TelegramRepo) PendingNotifications(ctx context.Context, limit int) ([]Notification, error) {
	rows, err := r.db.Queries.PendingNotifications(ctx, int32(limit))
	if err != nil {
		return nil, err
	}
	out := make([]Notification, 0, len(rows))
	for _, row := range rows {
		out = append(out, notificationFromSQLC(row))
	}
	return out, nil
}

// MarkNotificationSent stamps sent_at=NOW() on a delivered notification.
func (r *TelegramRepo) MarkNotificationSent(ctx context.Context, id int64) error {
	return r.db.Queries.MarkNotificationSent(ctx, id)
}

// RecentNotifications returns last notifications regardless of sent status.
func (r *TelegramRepo) RecentNotifications(ctx context.Context, limit int) ([]Notification, error) {
	rows, err := r.db.Queries.RecentNotifications(ctx, int32(limit))
	if err != nil {
		return nil, err
	}
	out := make([]Notification, 0, len(rows))
	for _, row := range rows {
		out = append(out, notificationFromSQLC(row))
	}
	return out, nil
}

// RecentDistinctNotifications returns recent unique notification events grouped
// by the alert dedupe key in payload when present, otherwise by type+payload.
// Telegram fan-out creates one notification per admin; this view is intended
// for compact UI timelines.
func (r *TelegramRepo) RecentDistinctNotifications(ctx context.Context, limit int) ([]Notification, error) {
	rows, err := r.db.Queries.RecentDistinctNotifications(ctx, int32(limit))
	if err != nil {
		return nil, err
	}
	out := make([]Notification, 0, len(rows))
	for _, row := range rows {
		out = append(out, notificationFromDistinctSQLC(row))
	}
	return out, nil
}

func (r *TelegramRepo) GetAlertState(ctx context.Context, dedupeKey string) (AlertState, bool, error) {
	row, err := r.db.Queries.GetAlertState(ctx, dedupeKey)
	if err != nil {
		if err == pgx.ErrNoRows {
			return AlertState{}, false, nil
		}
		return AlertState{}, false, err
	}
	return alertStateFromSQLC(row), true, nil
}

func (r *TelegramRepo) UpsertAlertState(ctx context.Context, s AlertState) error {
	payloadRaw, err := json.Marshal(s.LastPayload)
	if err != nil {
		return err
	}
	return r.db.Queries.UpsertAlertState(ctx, sqlc.UpsertAlertStateParams{
		DedupeKey:            s.DedupeKey,
		Type:                 s.Type,
		Severity:             s.Severity,
		Channel:              s.Channel,
		Status:               s.Status,
		ConsecutiveFailures:  int32(s.ConsecutiveFailures),
		ConsecutiveSuccesses: int32(s.ConsecutiveSuccesses),
		LastSentAt:           toPGTimePtr(s.LastSentAt),
		LastPayload:          payloadRaw,
	})
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

	qtx := r.db.Queries.WithTx(tx)
	notif, err = qtx.PruneSentNotifications(ctx)
	if err != nil {
		return 0, 0, 0, err
	}

	obs, err = qtx.PruneOldIPObservations(ctx)
	if err != nil {
		return 0, 0, 0, err
	}

	sig, err = qtx.PruneOldLeakSignals(ctx)
	if err != nil {
		return 0, 0, 0, err
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, 0, 0, err
	}
	return notif, obs, sig, nil
}
