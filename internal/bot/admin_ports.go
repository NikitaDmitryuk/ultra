package bot

import (
	"context"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

// botAdminRepo is the subset of db.BotAdminRepo used by the Telegram bot.
type botAdminRepo interface {
	IsAdmin(ctx context.Context, telegramID int64) (bool, error)
	ConsumeInviteToken(ctx context.Context, token string, telegramID int64, displayName string) error
	CreateInviteToken(ctx context.Context, token string) error
	ListAdmins(ctx context.Context) ([]db.BotAdmin, error)
	RemoveAdmin(ctx context.Context, telegramID int64) error
}
