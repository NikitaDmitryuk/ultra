package bot

import (
	"context"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

// alertsTeleRepo is the subset of db.TelegramRepo used by alert/outbox workers.
type alertsTeleRepo interface {
	EnqueueNotification(ctx context.Context, n db.Notification) error
	PendingNotifications(ctx context.Context, limit int) ([]db.Notification, error)
	MarkNotificationSent(ctx context.Context, id int64) error
}

// messageSender is the subset of tgbotapi.BotAPI used for delivering queued alerts.
type messageSender interface {
	Send(c tgbotapi.Chattable) (tgbotapi.Message, error)
}
