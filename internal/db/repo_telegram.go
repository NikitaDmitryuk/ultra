package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// Plan is a subscription tier (e.g. "100 GB / 30 days for N Stars").
type Plan struct {
	ID                int
	Name              string
	DurationDays      int
	TrafficLimitBytes *int64   // nil = unlimited
	PriceStars        *int     // Telegram Stars price; nil = not for sale via Stars
	PriceTON          *float64 // TON price; nil = not for sale via TON
	IsActive          bool
}

// Subscription is a user's active (or historical) plan instance.
type Subscription struct {
	ID                int64
	UserUUID          string
	PlanID            *int
	StartedAt         time.Time
	ExpiresAt         *time.Time
	TrafficLimitBytes *int64 // snapshot of plan limit at purchase time
	IsActive          bool
}

// Payment records a completed or pending payment event.
type Payment struct {
	ID               int64
	UserUUID         *string
	SubscriptionID   *int64
	Amount           float64
	Currency         string // "XTR" (Stars), "TON", "USDT", …
	TelegramChargeID *string
	Status           string // "pending" | "completed" | "refunded"
	CreatedAt        time.Time
}

// BotSession holds per-Telegram-user conversation state for the bot FSM.
type BotSession struct {
	TelegramID int64
	State      *string
	Data       map[string]any
	UpdatedAt  time.Time
}

// Notification is a queued message to deliver via Telegram.
type Notification struct {
	ID         int64
	UserUUID   *string
	TelegramID int64
	Type       string // e.g. "traffic_80pct", "expiry_3d", "payment_ok"
	Payload    map[string]any
	SentAt     *time.Time
	CreatedAt  time.Time
}

// TelegramRepo provides CRUD for plans, subscriptions, payments, bot sessions, and notifications.
type TelegramRepo struct {
	db *DB
}

// NewTelegramRepo creates a TelegramRepo backed by db.
func NewTelegramRepo(db *DB) *TelegramRepo { return &TelegramRepo{db: db} }

// ── Plans ────────────────────────────────────────────────────────────────────

// ListPlans returns all active plans ordered by id.
func (r *TelegramRepo) ListPlans(ctx context.Context) ([]Plan, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT id, name, duration_days, traffic_limit_bytes, price_stars, price_ton, is_active
		 FROM plans WHERE is_active=true ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var plans []Plan
	for rows.Next() {
		var p Plan
		if err := rows.Scan(&p.ID, &p.Name, &p.DurationDays, &p.TrafficLimitBytes,
			&p.PriceStars, &p.PriceTON, &p.IsActive); err != nil {
			return nil, err
		}
		plans = append(plans, p)
	}
	return plans, rows.Err()
}

// ── Subscriptions ─────────────────────────────────────────────────────────────

// CreateSubscription inserts a new subscription and returns its generated id.
func (r *TelegramRepo) CreateSubscription(ctx context.Context, s Subscription) (int64, error) {
	var id int64
	err := r.db.Pool.QueryRow(ctx,
		`INSERT INTO subscriptions(user_uuid, plan_id, started_at, expires_at, traffic_limit_bytes)
		 VALUES($1, $2, $3, $4, $5) RETURNING id`,
		s.UserUUID, s.PlanID, s.StartedAt, s.ExpiresAt, s.TrafficLimitBytes,
	).Scan(&id)
	return id, err
}

// ActiveSubscription returns the most recent active subscription for a user.
// Returns (zero, false, nil) when none exists.
func (r *TelegramRepo) ActiveSubscription(ctx context.Context, userUUID string) (Subscription, bool, error) {
	var s Subscription
	err := r.db.Pool.QueryRow(ctx,
		`SELECT id, user_uuid, plan_id, started_at, expires_at, traffic_limit_bytes, is_active
		 FROM subscriptions
		 WHERE user_uuid=$1 AND is_active=true
		 ORDER BY started_at DESC LIMIT 1`,
		userUUID,
	).Scan(&s.ID, &s.UserUUID, &s.PlanID, &s.StartedAt, &s.ExpiresAt, &s.TrafficLimitBytes, &s.IsActive)
	if errors.Is(err, pgx.ErrNoRows) {
		return Subscription{}, false, nil
	}
	if err != nil {
		return Subscription{}, false, err
	}
	return s, true, nil
}

// ── Payments ──────────────────────────────────────────────────────────────────

// CreatePayment inserts a payment record and returns its id.
func (r *TelegramRepo) CreatePayment(ctx context.Context, p Payment) (int64, error) {
	var id int64
	err := r.db.Pool.QueryRow(ctx,
		`INSERT INTO payments(user_uuid, subscription_id, amount, currency, telegram_charge_id, status)
		 VALUES($1, $2, $3, $4, $5, $6) RETURNING id`,
		p.UserUUID, p.SubscriptionID, p.Amount, p.Currency, p.TelegramChargeID, p.Status,
	).Scan(&id)
	return id, err
}

// UpdatePaymentStatus updates status and charge ID of an existing payment.
func (r *TelegramRepo) UpdatePaymentStatus(ctx context.Context, id int64, status, chargeID string) error {
	_, err := r.db.Pool.Exec(ctx,
		"UPDATE payments SET status=$1, telegram_charge_id=$2 WHERE id=$3",
		status, chargeID, id,
	)
	return err
}

// ── Bot Sessions ──────────────────────────────────────────────────────────────

// GetOrCreateSession returns the bot session for telegramID, creating it if absent.
func (r *TelegramRepo) GetOrCreateSession(ctx context.Context, telegramID int64) (BotSession, error) {
	sess := BotSession{TelegramID: telegramID}
	var dataRaw []byte
	err := r.db.Pool.QueryRow(ctx,
		`INSERT INTO bot_sessions(telegram_id)
		 VALUES($1)
		 ON CONFLICT(telegram_id) DO UPDATE SET telegram_id=EXCLUDED.telegram_id
		 RETURNING state, data, updated_at`,
		telegramID,
	).Scan(&sess.State, &dataRaw, &sess.UpdatedAt)
	if err != nil {
		return BotSession{}, err
	}
	if len(dataRaw) > 0 {
		_ = json.Unmarshal(dataRaw, &sess.Data)
	}
	return sess, nil
}

// SaveSession upserts conversation state for a Telegram user.
func (r *TelegramRepo) SaveSession(ctx context.Context, telegramID int64, state string, data map[string]any) error {
	dataRaw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	_, err = r.db.Pool.Exec(ctx,
		`INSERT INTO bot_sessions(telegram_id, state, data, updated_at)
		 VALUES($1, $2, $3, NOW())
		 ON CONFLICT(telegram_id) DO UPDATE SET state=$2, data=$3, updated_at=NOW()`,
		telegramID, state, dataRaw,
	)
	return err
}

// ── Notifications ─────────────────────────────────────────────────────────────

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
