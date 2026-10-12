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
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"golang.org/x/net/proxy"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

// Bot orchestrates long polling and the Mini App HTTP server.
type Bot struct {
	self                atomic.Pointer[tgbotapi.User]
	telegramLastSuccess atomic.Int64
	subscriptionCache   *subscriptionCache
	databaseReady       func(context.Context) bool
	memberships         membershipCache
	picker              memberPicker
	api                 *tgbotapi.BotAPI
	botToken            string
	adminRepo           botAdminRepo
	teleRepo            *db.TelegramRepo
	alertsTele          alertsTeleRepo
	msgSender           messageSender
	miniAppURL          string // public HTTPS URL of the Mini App (e.g. https://bot.example.com:8444)

	// Admin API proxy settings (ultra-relay admin HTTP API on loopback)
	adminAPIURL   string
	adminAPIToken string

	log *slog.Logger
}

// New creates a Bot connected to the Telegram Bot API.
// adminAPIURL is the base URL of the ultra-relay admin API (e.g. "http://127.0.0.1:8443").
// miniAppURL is the public HTTPS URL serving the embedded web frontend.
func New(
	botToken, adminAPIURL, adminAPIToken, miniAppURL string,
	adminRepo botAdminRepo,
	teleRepo *db.TelegramRepo,
	log *slog.Logger,
) (*Bot, error) {
	if botToken == "" {
		return nil, fmt.Errorf("bot: empty bot token")
	}
	if log == nil {
		log = slog.Default()
	}
	client := &http.Client{Timeout: 60 * time.Second}
	if socks := os.Getenv("ULTRA_BOT_TELEGRAM_SOCKS5"); socks != "" {
		var err error
		client, err = telegramHTTPClient(socks)
		if err != nil {
			return nil, err
		}
	}
	// Construction is entirely local: Telegram can be unavailable at startup.
	api := &tgbotapi.BotAPI{Token: botToken, Client: client, Buffer: 100}
	api.SetAPIEndpoint(tgbotapi.APIEndpoint)
	bot := &Bot{
		api:           api,
		botToken:      botToken,
		adminRepo:     adminRepo,
		teleRepo:      teleRepo,
		alertsTele:    teleRepo,
		msgSender:     api,
		miniAppURL:    miniAppURL,
		adminAPIURL:   adminAPIURL,
		adminAPIToken: adminAPIToken,
		log:           log,
	}
	return bot, nil
}

// RunPolling starts Telegram long polling and blocks until ctx is cancelled.
func (b *Bot) RunPolling(ctx context.Context) error {
	for attempt := 0; ctx.Err() == nil; attempt++ {
		var self tgbotapi.User
		if err := b.telegramJSON(ctx, "getMe", nil, &self); err == nil {
			b.self.Store(&self)
			return b.runMemberPolling(ctx)
		}
		if !waitTelegramRetry(ctx, retryDelay(attempt, 0)) {
			break
		}
	}
	return ctx.Err()
}

func (b *Bot) telegramSelf() tgbotapi.User {
	if self := b.self.Load(); self != nil {
		return *self
	}
	if b.api != nil {
		return b.api.Self
	}
	return tgbotapi.User{}
}

// Handler returns an http.Handler serving the Mini App API and embedded frontend.
// Call this to register routes on your HTTP server.
func (b *Bot) Handler() http.Handler {
	mux := http.NewServeMux()
	b.registerMiniAppRoutes(mux)
	b.registerHealthRoutes(mux)
	return withTimeout(30*time.Second, mux)
}

func withTimeout(d time.Duration, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), d)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func telegramHTTPClient(socksAddr string) (*http.Client, error) {
	if _, _, err := net.SplitHostPort(socksAddr); err != nil {
		return nil, fmt.Errorf("bot: invalid Telegram proxy address")
	}
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("bot: socks5 dialer: %w", err)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if ctxDialer, ok := dialer.(proxy.ContextDialer); ok {
				return ctxDialer.DialContext(ctx, network, addr)
			}
			return dialer.Dial(network, addr)
		},
	}
	return &http.Client{Transport: transport, Timeout: 60 * time.Second}, nil
}
