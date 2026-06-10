package db

import (
	"context"
	"errors"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
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
	return r.db.Queries.IsBotAdmin(ctx, telegramID)
}

// AddAdmin registers a Telegram user as a bot admin.
func (r *BotAdminRepo) AddAdmin(ctx context.Context, telegramID int64, name string) error {
	return r.db.Queries.UpsertBotAdmin(ctx, sqlc.UpsertBotAdminParams{TelegramID: telegramID, TelegramName: name})
}

// ListAdmins returns all registered bot admins.
func (r *BotAdminRepo) ListAdmins(ctx context.Context) ([]BotAdmin, error) {
	rows, err := r.db.Queries.ListBotAdmins(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]BotAdmin, 0, len(rows))
	for _, a := range rows {
		out = append(out, BotAdmin{TelegramID: a.TelegramID, TelegramName: a.TelegramName, AddedAt: timeFromPG(a.AddedAt)})
	}
	return out, nil
}

// RemoveAdmin removes a Telegram user from bot admins.
func (r *BotAdminRepo) RemoveAdmin(ctx context.Context, telegramID int64) error {
	return r.db.Queries.RemoveBotAdmin(ctx, telegramID)
}

// HasAnyAdmin returns true when at least one admin is registered.
func (r *BotAdminRepo) HasAnyAdmin(ctx context.Context) (bool, error) {
	return r.db.Queries.HasAnyBotAdmin(ctx)
}

// CreateInviteToken stores a new single-use invite token.
func (r *BotAdminRepo) CreateInviteToken(ctx context.Context, token string) error {
	return r.db.Queries.CreateInviteToken(ctx, token)
}

// ConsumeInviteToken validates the token, registers telegramID as admin, and marks the token used.
// Returns ErrInvalidToken if the token does not exist or was already consumed.
func (r *BotAdminRepo) ConsumeInviteToken(ctx context.Context, token string, telegramID int64, name string) error {
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	qtx := r.db.Queries.WithTx(tx)
	usedBy, err := qtx.GetInviteTokenUsedBy(ctx, token)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrInvalidToken
	}
	if err != nil {
		return err
	}
	if usedBy.Valid {
		return ErrInvalidToken
	}

	if err := qtx.UpsertBotAdmin(ctx, sqlc.UpsertBotAdminParams{TelegramID: telegramID, TelegramName: name}); err != nil {
		return err
	}

	if err := qtx.MarkInviteTokenUsed(ctx, sqlc.MarkInviteTokenUsedParams{UsedBy: pgtype.Int8{Int64: telegramID, Valid: true}, Token: token}); err != nil {
		return err
	}

	return tx.Commit(ctx)
}
