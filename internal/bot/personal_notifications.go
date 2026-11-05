package bot

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/adminapi"
	"github.com/NikitaDmitryuk/ultra/internal/db"
)

func (b *Bot) selfNotifications(w http.ResponseWriter, r *http.Request) {
	user, ok := b.selfAuth(w, r)
	if !ok {
		return
	}
	path := fmt.Sprintf("/v1/members/%d/notifications", user.ID)
	var p db.PersonalNotificationPreferences
	var input any
	if r.Method == "PUT" {
		v, e := adminapi.DecodePersonalPreferences(http.MaxBytesReader(w, r.Body, 1024))
		if e != nil {
			http.Error(w, "four boolean preferences required", 400)
			return
		}
		input = v
	}
	status, e := b.relayJSON(r.Context(), r.Method, path, input, &p)
	if e != nil {
		memberHTTPError(w, status)
		return
	}
	jsonOK(w, p)
}

func (b *Bot) personalNotifications(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c, cancel := context.WithTimeout(ctx, 8*time.Second)
			_, _ = b.relayJSON(c, "POST", "/v1/personal-notifications/observe", nil, nil)
			cancel()
			for i := 0; i < 20 && ctx.Err() == nil; i++ {
				if !b.sendPersonalNotification(ctx) {
					break
				}
			}
		}
	}
}
func personalNotificationText(n db.PersonalNotification, subscription string) string {
	switch n.Category {
	case "credentials":
		cause := "Изменён ключ VPN (UUID)."
		if n.Kind == "subscription_token" {
			cause = "Изменена ссылка подписки VPN."
		}
		return cause + " Обновите подписку в приложении:\n" + subscription
	case "access":
		if n.Kind == "enabled" {
			return "Доступ к VPN включён. Настройки применены."
		}
		return "Доступ к VPN отключён."
	case "quota":
		if n.Kind == "restored" {
			return "Ограничение по квоте снято. Доступность VPN проверяется отдельно."
		}
		return "Квота исчерпана для всех доступных маршрутов VPN."
	case "availability":
		if n.Kind == "recovered" {
			return "Доступность VPN восстановлена и подтверждена проверками."
		}
		return "VPN недоступен по всем доступным маршрутам более 5 минут. Проверки продолжаются."
	}
	return ""
}

// sendPersonalNotification keeps all user secrets outside durable payloads and
// logs. A prepare call reads/decrypts only an already existing current token.
func (b *Bot) sendPersonalNotification(ctx context.Context) bool {
	var n db.PersonalNotification
	status, e := b.relayJSON(ctx, "POST", "/v1/personal-notifications/claim", nil, &n)
	if e != nil {
		return false
	}
	if status == 404 {
		return false
	}
	complete := func(sent, terminal, deferred bool, delay int) {
		_, err := b.relayJSON(
			ctx,
			"POST",
			fmt.Sprintf("/v1/personal-notifications/%d/complete", n.ID),
			map[string]any{"notification": n, "sent": sent, "terminal": terminal, "deferred": deferred, "delay_seconds": delay},
			nil,
		)
		if err != nil && b.log != nil {
			b.log.Warn("personal notification acknowledgement unavailable")
		}
	}
	var prepared struct {
		Eligible     bool                    `json:"eligible"`
		Pending      bool                    `json:"pending"`
		Notification db.PersonalNotification `json:"notification"`
		Token        string                  `json:"token"`
	}
	prepare := func() error {
		_, err := b.relayJSON(ctx, "POST", fmt.Sprintf("/v1/personal-notifications/%d/prepare", n.ID), n, &prepared)
		return err
	}
	if e = prepare(); e != nil {
		complete(false, false, false, 60)
		return true
	}
	if prepared.Pending {
		complete(false, false, true, 60)
		return true
	}
	if !prepared.Eligible {
		complete(false, true, false, 0)
		return true
	}
	n = prepared.Notification
	// Recheck immediately before Telegram, after any credential rendering work.
	if e = prepare(); e != nil {
		complete(false, false, false, 60)
		return true
	}
	if prepared.Pending {
		complete(false, false, true, 60)
		return true
	}
	if !prepared.Eligible {
		complete(false, true, false, 0)
		return true
	}
	n = prepared.Notification
	base, e := url.Parse(b.miniAppURL)
	if e != nil || base.Scheme != "https" || base.Host == "" || base.User != nil {
		complete(false, false, false, 60)
		return true
	}
	base.RawQuery = ""
	base.Fragment = ""
	base.RawPath = ""
	subscription := ""
	if n.Category == "credentials" {
		if prepared.Token == "" || b.miniAppURL == "" {
			complete(false, false, false, 60)
			return true
		}
		base.Path = "/sub/" + prepared.Token
		subscription = base.String()
	}
	text := personalNotificationText(n, subscription)
	if text == "" {
		complete(false, true, false, 0)
		return true
	}
	input := map[string]any{"chat_id": n.TelegramID, "text": text, "disable_web_page_preview": true}
	if b.miniAppURL != "" {
		base.Path = "/member"
		input["reply_markup"] = webAppMarkup("Мой VPN", base.String())
	}
	c, cancel := context.WithTimeout(ctx, 8*time.Second)
	e = b.telegramJSON(c, "sendMessage", input, nil)
	cancel()
	if e == nil {
		complete(true, false, false, 0)
		return true
	}
	// Telegram 403 means blocked/deactivated; no future retry for this event.
	after, permanent := telegramFailure(e)
	delay := min(int((retryDelay(n.DeliveryAttempts, after)+time.Second-1)/time.Second), 24*60*60)
	complete(false, permanent, false, delay)
	return true
}
