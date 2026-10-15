package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Notification is a queued message to deliver via Telegram.
type Notification struct {
	Attempts   int
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
	n := notificationFromFields(row.ID, row.UserUuid, row.TelegramID, row.Type, row.Payload, row.SentAt, row.CreatedAt)
	n.Attempts = int(row.Attempts)
	return n
}

func notificationFromDistinctSQLC(row sqlc.RecentDistinctNotificationsRow) Notification {
	return notificationFromFields(row.ID, row.UserUuid, row.TelegramID, row.Type, row.Payload, row.SentAt, row.CreatedAt)
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
	return r.db.orm.WithContext(ctx).
		Select("user_uuid", "telegram_id", "type", "payload", "sent_at").
		Create(&notificationRow{UserUUID: ptrFromPGUUID(userUUID), TelegramID: n.TelegramID, Type: n.Type, Payload: payloadRaw, SentAt: n.SentAt}).
		Error
}

// PendingNotifications returns up to limit unsent notifications ordered by creation time.
func (r *TelegramRepo) PendingNotifications(ctx context.Context, limit int) ([]Notification, error) {
	if limit < 0 {
		return nil, errors.New("limit must not be negative")
	}
	rows := []notificationRow{}
	if err := r.db.orm.WithContext(ctx).Where("sent_at IS NULL").Order("created_at").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Notification, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.notification())
	}
	return out, nil
}

// MarkNotificationSent stamps sent_at=NOW() on a delivered notification.
func (r *TelegramRepo) MarkNotificationSent(ctx context.Context, id int64) error {
	return r.db.orm.WithContext(ctx).Table("notifications").Where("id = ?", id).Update("sent_at", gorm.Expr("NOW()")).Error
}

// RecentNotifications returns last notifications regardless of sent status.
func (r *TelegramRepo) RecentNotifications(ctx context.Context, limit int) ([]Notification, error) {
	if limit < 0 {
		return nil, errors.New("limit must not be negative")
	}
	rows := []notificationRow{}
	if err := r.db.orm.WithContext(ctx).Order("created_at DESC").Limit(limit).Find(&rows).Error; err != nil {
		return nil, err
	}
	out := make([]Notification, 0, len(rows))
	for _, row := range rows {
		out = append(out, row.notification())
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
	var row alertStateRow
	err := cloudLookupError(r.db.orm.WithContext(ctx).Where("dedupe_key = ?", dedupeKey).Take(&row).Error)
	if err != nil {
		if err == pgx.ErrNoRows {
			return AlertState{}, false, nil
		}
		return AlertState{}, false, err
	}
	return row.state(), true, nil
}

func (r *TelegramRepo) UpsertAlertState(ctx context.Context, s AlertState) error {
	payloadRaw, err := json.Marshal(s.LastPayload)
	if err != nil {
		return err
	}
	row := map[string]any{
		"dedupe_key":            s.DedupeKey,
		"type":                  s.Type,
		"severity":              s.Severity,
		"channel":               s.Channel,
		"status":                s.Status,
		"consecutive_failures":  int32(s.ConsecutiveFailures),
		"consecutive_successes": int32(s.ConsecutiveSuccesses),
		"last_seen_at":          gorm.Expr("NOW()"),
		"last_sent_at":          s.LastSentAt,
		"last_payload":          payloadRaw,
		"updated_at":            gorm.Expr("NOW()"),
	}
	return r.db.orm.WithContext(ctx).
		Table("alert_state").
		Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "dedupe_key"}}, DoUpdates: clause.AssignmentColumns([]string{"type", "severity", "channel", "status", "consecutive_failures", "consecutive_successes", "last_seen_at", "last_sent_at", "last_payload", "updated_at"})}).
		Create(row).
		Error
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

type MemberNotification struct {
	MemberID, AdminID int64
	Name, Source      string
	Attempts          int
}

func (r *TelegramRepo) ClaimMemberNotifications(ctx context.Context) ([]MemberNotification, error) {
	rows, e := r.db.Pool.Query(ctx, `WITH due AS (
 SELECT n.member_id,n.admin_id FROM vpn_member_notifications n JOIN users u ON u.telegram_id=n.member_id
 WHERE n.sent_at IS NULL AND NOT n.terminal AND n.next_attempt<=NOW() AND (n.lease_until IS NULL OR n.lease_until<=NOW()) AND NOT u.member_pending ORDER BY n.created_at LIMIT 1 FOR UPDATE OF n SKIP LOCKED
 ), claimed AS (UPDATE vpn_member_notifications n SET attempts=attempts+1,next_attempt=NOW()+INTERVAL '1 minute',lease_until=NOW()+INTERVAL '1 minute'
 FROM due WHERE n.member_id=due.member_id AND n.admin_id=due.admin_id RETURNING n.member_id,n.admin_id,n.attempts)
 SELECT c.member_id,c.admin_id,u.name,u.enrollment_source,c.attempts FROM claimed c JOIN users u ON u.telegram_id=c.member_id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []MemberNotification{}
	for rows.Next() {
		var n MemberNotification
		if e = rows.Scan(&n.MemberID, &n.AdminID, &n.Name, &n.Source, &n.Attempts); e != nil {
			return nil, e
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
func (r *TelegramRepo) MemberNotificationSent(ctx context.Context, member, admin int64) error {
	return r.db.orm.WithContext(ctx).
		Table("vpn_member_notifications").
		Where("member_id = ? AND admin_id = ?", member, admin).
		Update("sent_at", gorm.Expr("NOW()")).
		Error
}

func (r *TelegramRepo) ClaimNotifications(ctx context.Context, limit int, lease time.Duration) ([]Notification, error) {
	rows, err := r.db.Queries.ClaimNotifications(ctx, sqlc.ClaimNotificationsParams{Limit: int32(limit), Lease: toPGInterval(lease)})
	if err != nil {
		return nil, err
	}
	out := make([]Notification, 0, len(rows))
	for _, row := range rows {
		out = append(out, notificationFromSQLC(row))
	}
	return out, nil
}
func (r *TelegramRepo) CompleteNotification(ctx context.Context, id int64) error {
	return r.db.Queries.CompleteNotification(ctx, id)
}
func (r *TelegramRepo) RetryNotification(ctx context.Context, id int64, next time.Time, lastError string, terminal bool) error {
	return r.db.Queries.RetryNotification(
		ctx,
		sqlc.RetryNotificationParams{ID: id, NextAttemptAt: toPGTime(next), LastError: lastError, Terminal: terminal},
	)
}

// CompleteClaim rejects acknowledgements from a worker whose lease was replaced.
func (r *TelegramRepo) CompleteClaim(ctx context.Context, id int64, attempt int) error {
	n, err := r.db.Queries.CompleteNotificationClaim(ctx, sqlc.CompleteNotificationClaimParams{ID: id, Attempts: int32(attempt)})
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("notification lease lost")
	}
	return nil
}
func (r *TelegramRepo) RetryClaim(ctx context.Context, id int64, attempt int, next time.Time, lastError string, terminal bool) error {
	n, err := r.db.Queries.RetryNotificationClaim(
		ctx,
		sqlc.RetryNotificationClaimParams{
			ID:            id,
			Attempts:      int32(attempt),
			NextAttemptAt: toPGTime(next),
			LastError:     lastError,
			Terminal:      terminal,
		},
	)
	if err != nil {
		return err
	}
	if n == 0 {
		return errors.New("notification lease lost")
	}
	return nil
}

func (r *TelegramRepo) CompleteMemberClaim(ctx context.Context, member, admin int64, attempt int) error {
	tag, err := r.db.Pool.Exec(
		ctx,
		`UPDATE vpn_member_notifications SET sent_at=NOW(),lease_until=NULL,last_error='' WHERE member_id=$1 AND admin_id=$2 AND attempts=$3 AND sent_at IS NULL AND next_attempt>NOW() AND lease_until>NOW()`,
		member,
		admin,
		attempt,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("member notification lease lost")
	}
	return nil
}

func (r *TelegramRepo) RetryMemberNotification(
	ctx context.Context,
	member, admin int64,
	attempt int,
	next time.Time,
	lastError string,
	terminal bool,
) error {
	tag, err := r.db.Pool.Exec(
		ctx,
		`UPDATE vpn_member_notifications SET next_attempt=$4,last_error=$5,terminal=$6,lease_until=NULL WHERE member_id=$1 AND admin_id=$2 AND attempts=$3 AND sent_at IS NULL AND next_attempt>NOW() AND lease_until>NOW()`,
		member,
		admin,
		attempt,
		next,
		lastError,
		terminal,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errors.New("member notification lease lost")
	}
	return nil
}
