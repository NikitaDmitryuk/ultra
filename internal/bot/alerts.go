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
	exitProbeInterval       = 60 * time.Second
	trafficSpikeInterval    = time.Hour
	outboxSendInterval      = 10 * time.Second
	trafficSpikeBytes       = int64(5 * 1024 * 1024 * 1024) // 5 GiB/hour
	exitDownConfirmSamples  = 3
	exitUpConfirmSamples    = 2
	exitFailoverConfirmHits = 2
	exitAlertCooldown       = 30 * time.Minute
	failoverAlertCooldown   = 10 * time.Minute
	trafficSpikeCooldown    = 6 * time.Hour
)

type exitAlertState struct {
	initialized       bool
	activeID          string
	reachable         bool
	downStreak        int
	upStreak          int
	pendingActiveID   string
	pendingActiveHits int
}

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

	var exitState exitAlertState
	prevTotals := map[string]int64{}

	b.captureTrafficSnapshot(ctx, prevTotals)

	for {
		select {
		case <-ctx.Done():
			return
		case <-exitTicker.C:
			b.probeExitAlerts(ctx, &exitState)
		case <-spikeTicker.C:
			b.checkTrafficSpikes(ctx, prevTotals)
		}
	}
}

func (b *Bot) probeExitAlerts(ctx context.Context, st *exitAlertState) {
	body, err := b.adminGet(ctx, "/v1/health")
	if err != nil {
		b.log.Warn("alerts: /v1/health failed", "err", err)
		return
	}
	var h struct {
		ActiveExitID string `json:"active_exit_id"`
		Exit         struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			Reachable bool   `json:"reachable"`
		} `json:"exit"`
	}
	if err := json.Unmarshal(body, &h); err != nil {
		b.log.Warn("alerts: decode /v1/health", "err", err)
		return
	}
	activeID := h.ActiveExitID
	if activeID == "" {
		activeID = h.Exit.ID
	}
	exitName := h.Exit.Name
	if exitName == "" {
		exitName = "exit"
	}
	reachable := h.Exit.Reachable

	if !st.initialized {
		st.initialized = true
		st.activeID = activeID
		st.reachable = reachable
		return
	}

	if st.activeID == "" && activeID != "" {
		st.activeID = activeID
		st.reachable = reachable
	}

	if st.activeID != "" && activeID != "" && st.activeID != activeID {
		if st.pendingActiveID == activeID {
			st.pendingActiveHits++
		} else {
			st.pendingActiveID = activeID
			st.pendingActiveHits = 1
		}
		if st.pendingActiveHits >= exitFailoverConfirmHits {
			payload := map[string]any{
				"text": fmt.Sprintf("Active exit переключена: %s → %s.", st.activeID, activeID),
				"from": st.activeID,
				"to":   activeID,
			}
			b.enqueueAdminAlertWithCooldown(ctx, "exit_failover", payload, map[string]any{
				"from": st.activeID,
				"to":   activeID,
			}, failoverAlertCooldown)
			st.activeID = activeID
			st.reachable = reachable
			st.downStreak = 0
			st.upStreak = 0
			st.pendingActiveID = ""
			st.pendingActiveHits = 0
		}
	} else {
		st.pendingActiveID = ""
		st.pendingActiveHits = 0
	}

	if reachable == st.reachable {
		st.downStreak = 0
		st.upStreak = 0
		return
	}
	if !reachable {
		st.downStreak++
		st.upStreak = 0
		if st.downStreak < exitDownConfirmSamples {
			return
		}
		b.enqueueAdminAlertWithCooldown(ctx, "exit_down", map[string]any{
			"text":    fmt.Sprintf("Exit «%s» недоступна (bridge↔exit probe failed).", exitName),
			"exit_id": activeID,
		}, map[string]any{
			"exit_id": activeID,
		}, exitAlertCooldown)
		st.reachable = false
		st.downStreak = 0
		return
	}

	st.upStreak++
	st.downStreak = 0
	if st.upStreak < exitUpConfirmSamples {
		return
	}
	b.enqueueAdminAlertWithCooldown(ctx, "exit_up", map[string]any{
		"text":    fmt.Sprintf("Exit «%s» снова доступна.", exitName),
		"exit_id": activeID,
	}, map[string]any{
		"exit_id": activeID,
	}, exitAlertCooldown)
	st.reachable = true
	st.upStreak = 0
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
		payload := map[string]any{
			"user_uuid":   r.UserUUID,
			"delta_bytes": delta,
			"text":        fmt.Sprintf("Резкий рост трафика: %s за последний час.", humanBytes(delta)),
		}
		b.enqueueAdminAlertWithCooldown(ctx, "traffic_spike", payload, map[string]any{
			"user_uuid": r.UserUUID,
		}, trafficSpikeCooldown)
	}
}

func (b *Bot) enqueueAdminAlertWithCooldown(
	ctx context.Context,
	typ string,
	payload map[string]any,
	cooldownMatch map[string]any,
	cooldown time.Duration,
) {
	if cooldown > 0 && b.alertsTele != nil {
		recent, err := b.alertsTele.HasRecentNotification(ctx, typ, cooldownMatch, cooldown)
		if err != nil {
			b.log.Warn("alerts: cooldown check failed", "type", typ, "err", err)
		} else if recent {
			return
		}
	}
	b.enqueueAdminAlert(ctx, typ, payload)
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
	case "exit_failover":
		return "Active exit переключена на резервную."
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
