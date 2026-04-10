// Package bot implements the Telegram bot and Mini App HTTP server for ultra-relay administration.
//
// The bot runs on the bridge server using long polling (no webhook required).
// Admins authenticate via /start <invite_token>; subsequent interactions use
// Telegram Mini App with initData HMAC validation.
package bot

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

// Bot orchestrates long polling and the Mini App HTTP server.
type Bot struct {
	api        *tgbotapi.BotAPI
	botToken   string
	adminRepo  *db.BotAdminRepo
	miniAppURL string // public HTTPS URL of the Mini App (e.g. https://bot.example.com:8444)

	// Admin API proxy settings (ultra-relay admin HTTP API on loopback)
	adminAPIURL   string
	adminAPIToken string

	log *slog.Logger
}

// New creates a Bot connected to the Telegram Bot API.
// adminAPIURL is the base URL of the ultra-relay admin API (e.g. "http://127.0.0.1:8443").
// miniAppURL is the public HTTPS URL serving the embedded web frontend.
func New(botToken, adminAPIURL, adminAPIToken, miniAppURL string, adminRepo *db.BotAdminRepo, log *slog.Logger) (*Bot, error) {
	if botToken == "" {
		return nil, fmt.Errorf("bot: empty bot token")
	}
	api, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		return nil, fmt.Errorf("bot: connect to Telegram API: %w", err)
	}
	if log == nil {
		log = slog.Default()
	}
	log.Info("bot authenticated", "username", api.Self.UserName)
	return &Bot{
		api:           api,
		botToken:      botToken,
		adminRepo:     adminRepo,
		miniAppURL:    miniAppURL,
		adminAPIURL:   adminAPIURL,
		adminAPIToken: adminAPIToken,
		log:           log,
	}, nil
}

// RunPolling starts Telegram long polling and blocks until ctx is cancelled.
func (b *Bot) RunPolling(ctx context.Context) error {
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60
	updates := b.api.GetUpdatesChan(u)
	b.log.Info("bot polling started")
	for {
		select {
		case <-ctx.Done():
			b.api.StopReceivingUpdates()
			return ctx.Err()
		case update, ok := <-updates:
			if !ok {
				return nil
			}
			go b.handleUpdate(ctx, update)
		}
	}
}

// Handler returns an http.Handler serving the Mini App API and embedded frontend.
// Call this to register routes on your HTTP server.
func (b *Bot) Handler() http.Handler {
	mux := http.NewServeMux()
	b.registerMiniAppRoutes(mux)
	return withTimeout(30*time.Second, mux)
}

func withTimeout(d time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
