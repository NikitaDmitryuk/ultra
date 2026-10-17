package bot

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/http"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

func retryDelay(attempt, retryAfter int) time.Duration {
	if retryAfter > 0 {
		return time.Duration(retryAfter) * time.Second
	}
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 10 {
		attempt = 10
	}
	d := min(time.Second*time.Duration(1<<attempt), 15*time.Minute)
	return d + time.Duration(rand.Int64N(int64(d/4)+1))
}

func telegramFailure(err error) (retryAfter int, terminal bool) {
	var apiErr tgbotapi.Error
	if !errors.As(err, &apiErr) {
		var pointer *tgbotapi.Error
		if !errors.As(err, &pointer) || pointer == nil {
			return 0, false
		}
		apiErr = *pointer
	}
	return apiErr.RetryAfter, apiErr.Code == 400 || apiErr.Code == 403
}

func waitTelegramRetry(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (b *Bot) SetDatabaseProbe(probe func(context.Context) bool) { b.databaseReady = probe }

func (b *Bot) registerHealthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"alive":true}`))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		database := b.databaseReady != nil && b.databaseReady(ctx)
		control := false
		if database {
			body, err := b.adminGet(ctx, "/v1/hardening")
			if err == nil {
				var status struct {
					Runtime struct {
						Mode string `json:"mode"`
					} `json:"runtime"`
				}
				control = json.Unmarshal(body, &status) == nil && status.Runtime.Mode == "online"
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if !control {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).
			Encode(map[string]any{"ready": control, "database": database, "relay": control, "telegram": time.Since(time.Unix(0, b.telegramLastSuccess.Load())) < 2*time.Minute, "subscription_cache": b.subscriptionCache != nil && b.subscriptionCache.fresh()})
	})
}
