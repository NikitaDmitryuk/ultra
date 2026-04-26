package bot

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

const (
	exitProbeInterval    = 60 * time.Second
	trafficSpikeInterval = time.Hour
	outboxSendInterval   = 10 * time.Second
	trafficSpikeBytes    = int64(5 * 1024 * 1024 * 1024) // 5 GiB/hour
)

func (b *Bot) StartWorkers(ctx context.Context) {
	if b.alertsTele == nil {
		b.log.Warn("alerts worker disabled: telegram repo is nil")
		return
	}
	go b.runAlertsWorker(ctx)
	go b.runOutboxSender(ctx)
	go b.runLeakDetector(ctx)
	go b.runMaintenance(ctx)
}

func (b *Bot) runAlertsWorker(ctx context.Context) {
	exitTicker := time.NewTicker(exitProbeInterval)
	defer exitTicker.Stop()
	spikeTicker := time.NewTicker(trafficSpikeInterval)
	defer spikeTicker.Stop()

	var lastExitState string
	prevTotals := map[string]int64{}

	b.captureTrafficSnapshot(ctx, prevTotals)

	for {
		select {
		case <-ctx.Done():
			return
		case <-exitTicker.C:
			state := b.probeExitState(ctx)
			if state == "" {
				continue
			}
			if lastExitState != "" && state != lastExitState {
				if state == "down" {
					b.enqueueAdminAlert(ctx, "exit_down", map[string]any{
						"text": "Exit-нода недоступна (bridge↔exit probe failed).",
					})
				} else {
					b.enqueueAdminAlert(ctx, "exit_up", map[string]any{
						"text": "Exit-нода снова доступна.",
					})
				}
			}
			lastExitState = state
		case <-spikeTicker.C:
			b.checkTrafficSpikes(ctx, prevTotals)
		}
	}
}

func (b *Bot) probeExitState(ctx context.Context) string {
	body, err := b.adminGet(ctx, "/v1/health")
	if err != nil {
		b.log.Warn("alerts: /v1/health failed", "err", err)
		return ""
	}
	var h struct {
		Exit struct {
			Reachable bool `json:"reachable"`
		} `json:"exit"`
	}
	if err := json.Unmarshal(body, &h); err != nil {
		b.log.Warn("alerts: decode /v1/health", "err", err)
		return ""
	}
	if !h.Exit.Reachable {
		return "down"
	}
	return "up"
}

func (b *Bot) captureTrafficSnapshot(ctx context.Context, dst map[string]int64) {
	body, err := b.adminGet(ctx, "/v1/traffic/monthly")
	if err != nil {
		b.log.Warn("alerts: traffic snapshot failed", "err", err)
		return
	}
	var rows []struct {
		UserUUID   string `json:"UserUUID"`
		TotalBytes int64  `json:"TotalBytes"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		b.log.Warn("alerts: decode monthly traffic", "err", err)
		return
	}
	for _, r := range rows {
		dst[r.UserUUID] = r.TotalBytes
	}
}

func (b *Bot) checkTrafficSpikes(ctx context.Context, prev map[string]int64) {
	body, err := b.adminGet(ctx, "/v1/traffic/monthly")
	if err != nil {
		b.log.Warn("alerts: traffic_spike read monthly", "err", err)
		return
	}
	var rows []struct {
		UserUUID   string `json:"UserUUID"`
		TotalBytes int64  `json:"TotalBytes"`
	}
	if err := json.Unmarshal(body, &rows); err != nil {
		b.log.Warn("alerts: traffic_spike decode", "err", err)
		return
	}
	for _, r := range rows {
		delta := r.TotalBytes - prev[r.UserUUID]
		prev[r.UserUUID] = r.TotalBytes
		if delta <= trafficSpikeBytes {
			continue
		}
		b.enqueueAdminAlert(ctx, "traffic_spike", map[string]any{
			"user_uuid":   r.UserUUID,
			"delta_bytes": delta,
			"text":        fmt.Sprintf("Резкий рост трафика: %s за последний час.", humanBytes(delta)),
		})
	}
}

func (b *Bot) enqueueAdminAlert(ctx context.Context, typ string, payload map[string]any) {
	admins, err := b.adminRepo.ListAdmins(ctx)
	if err != nil {
		b.log.Warn("alerts: list admins", "err", err)
		return
	}
	for _, a := range admins {
		if err := b.alertsTele.EnqueueNotification(ctx, db.Notification{
			TelegramID: a.TelegramID,
			Type:       typ,
			Payload:    payload,
		}); err != nil {
			b.log.Warn("alerts: enqueue notification failed", "type", typ, "tg_id", a.TelegramID, "err", err)
		}
	}
}

func (b *Bot) runOutboxSender(ctx context.Context) {
	ticker := time.NewTicker(outboxSendInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			b.flushOutboxOnce(ctx)
		}
	}
}

func (b *Bot) flushOutboxOnce(ctx context.Context) {
	list, err := b.alertsTele.PendingNotifications(ctx, 50)
	if err != nil {
		b.log.Warn("outbox: pending notifications", "err", err)
		return
	}
	for _, n := range list {
		msg := tgbotapi.NewMessage(n.TelegramID, formatNotificationText(n))
		_, sendErr := b.msgSender.Send(msg)
		if sendErr != nil {
			b.log.Warn("outbox: telegram send failed", "id", n.ID, "tg_id", n.TelegramID, "err", sendErr)
		}
		if err := b.alertsTele.MarkNotificationSent(ctx, n.ID); err != nil {
			b.log.Warn("outbox: mark sent failed", "id", n.ID, "err", err)
		}
	}
}

func formatNotificationText(n db.Notification) string {
	text, _ := n.Payload["text"].(string)
	if text != "" {
		return text
	}
	switch n.Type {
	case "exit_down":
		return "Exit-нода недоступна."
	case "exit_up":
		return "Exit-нода снова доступна."
	case "traffic_spike":
		return "Обнаружен резкий рост трафика."
	case "token_leak":
		return "Обнаружена подозрительная активность по токену."
	case "test_alert":
		return "Тестовое уведомление от Mini App."
	default:
		return "Новое событие мониторинга."
	}
}

func humanBytes(v int64) string {
	if v <= 0 {
		return "0 B"
	}
	units := []string{"B", "KB", "MB", "GB", "TB"}
	f := float64(v)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", f, units[i])
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}
