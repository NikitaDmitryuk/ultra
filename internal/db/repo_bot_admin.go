package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// ErrInvalidToken is returned when an invite token does not exist or is already used.
var ErrInvalidToken = errors.New("db: invalid or already used invite token")

// BotAdmin is a Telegram user registered as a bot administrator.
type BotAdmin struct {
	TelegramID   int64
	TelegramName string
	AddedAt      time.Time
}

// BotAdminRepo handles bot admin and invite token operations.
type BotAdminRepo struct {
	db *DB
}

// NewBotAdminRepo creates a BotAdminRepo backed by db.
func NewBotAdminRepo(db *DB) *BotAdminRepo { return &BotAdminRepo{db: db} }

// IsAdmin returns true if telegramID is a registered bot admin.
func (r *BotAdminRepo) IsAdmin(ctx context.Context, telegramID int64) (bool, error) {
	var exists bool
	err := r.db.Pool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM bot_admins WHERE telegram_id=$1)", telegramID,
	).Scan(&exists)
	return exists, err
}

// AddAdmin registers a Telegram user as a bot admin.
func (r *BotAdminRepo) AddAdmin(ctx context.Context, telegramID int64, name string) error {
	_, err := r.db.Pool.Exec(ctx,
		`INSERT INTO bot_admins(telegram_id, telegram_name) VALUES($1, $2)
		 ON CONFLICT(telegram_id) DO UPDATE SET telegram_name=$2`,
		telegramID, name,
	)
	return err
}

// ListAdmins returns all registered bot admins.
func (r *BotAdminRepo) ListAdmins(ctx context.Context) ([]BotAdmin, error) {
	rows, err := r.db.Pool.Query(ctx,
		"SELECT telegram_id, telegram_name, added_at FROM bot_admins ORDER BY added_at",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BotAdmin
	for rows.Next() {
		var a BotAdmin
		if err := rows.Scan(&a.TelegramID, &a.TelegramName, &a.AddedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// RemoveAdmin removes a Telegram user from bot admins.
func (r *BotAdminRepo) RemoveAdmin(ctx context.Context, telegramID int64) error {
	_, err := r.db.Pool.Exec(ctx,
		"DELETE FROM bot_admins WHERE telegram_id=$1", telegramID,
	)
	return err
}

// HasAnyAdmin returns true when at least one admin is registered.
func (r *BotAdminRepo) HasAnyAdmin(ctx context.Context) (bool, error) {
	var exists bool
	err := r.db.Pool.QueryRow(ctx,
		"SELECT EXISTS(SELECT 1 FROM bot_admins)",
	).Scan(&exists)
	return exists, err
}

// CreateInviteToken stores a new single-use invite token.
func (r *BotAdminRepo) CreateInviteToken(ctx context.Context, token string) error {
	_, err := r.db.Pool.Exec(ctx,
		"INSERT INTO bot_invite_tokens(token) VALUES($1)", token,
	)
	return err
}

// ConsumeInviteToken validates the token, registers telegramID as admin, and marks the token used.
// Returns ErrInvalidToken if the token does not exist or was already consumed.
func (r *BotAdminRepo) ConsumeInviteToken(ctx context.Context, token string, telegramID int64, name string) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var usedBy *int64
	err = tx.QueryRow(ctx,
		"SELECT used_by FROM bot_invite_tokens WHERE token=$1", token,
	).Scan(&usedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidToken
	}
	if err != nil {
		return err
	}
	if usedBy != nil {
		return ErrInvalidToken
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO bot_admins(telegram_id, telegram_name) VALUES($1, $2)
		 ON CONFLICT(telegram_id) DO UPDATE SET telegram_name=$2`,
		telegramID, name,
	); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx,
		"UPDATE bot_invite_tokens SET used_by=$1, used_at=NOW() WHERE token=$2",
		telegramID, token,
	); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
