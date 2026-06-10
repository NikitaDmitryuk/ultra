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

	exitHealthStatePrefix = "exit.active.health:"
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
		b.initExitAlertState(ctx, st, activeID)
		if reachable && st.reachable {
			b.saveExitAlertState(ctx, st)
			return
		}
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
			b.emitAlert(ctx, alertEvent{
				DedupeKey: "exit.active.failover:" + st.activeID + ":" + activeID,
				Type:      "exit_failover",
				Severity:  alertSeverityCritical,
				Channel:   alertChannelTelegram,
				Status:    "fired",
				Payload:   payload,
				Cooldown:  failoverAlertCooldown,
			})
			st.activeID = activeID
			st.reachable = reachable
			st.downStreak = 0
			st.upStreak = 0
			st.pendingActiveID = ""
			st.pendingActiveHits = 0
			b.saveExitAlertState(ctx, st)
		}
	} else {
		st.pendingActiveID = ""
		st.pendingActiveHits = 0
	}

	if reachable == st.reachable {
		st.downStreak = 0
		st.upStreak = 0
		b.saveExitAlertState(ctx, st)
		return
	}
	if !reachable {
		st.downStreak++
		st.upStreak = 0
		if st.downStreak < exitDownConfirmSamples {
			b.saveExitAlertState(ctx, st)
			return
		}
		b.emitAlert(ctx, alertEvent{
			DedupeKey: "exit.active.down:" + activeID,
			Type:      "exit_down",
			Severity:  alertSeverityCritical,
			Channel:   alertChannelTelegram,
			Status:    "fired",
			Payload: map[string]any{
				"text":    fmt.Sprintf("Exit «%s» недоступна (bridge↔exit probe failed).", exitName),
				"exit_id": activeID,
			},
			Cooldown: exitAlertCooldown,
		})
		st.reachable = false
		st.downStreak = 0
		b.saveExitAlertState(ctx, st)
		return
	}

	st.upStreak++
	st.downStreak = 0
	if st.upStreak < exitUpConfirmSamples {
		b.saveExitAlertState(ctx, st)
		return
	}
	b.emitAlert(ctx, alertEvent{
		DedupeKey: "exit.active.up:" + activeID,
		Type:      "exit_up",
		Severity:  alertSeverityInfo,
		Channel:   alertChannelTelegram,
		Status:    "resolved",
		Payload: map[string]any{
			"text":    fmt.Sprintf("Exit «%s» снова доступна.", exitName),
			"exit_id": activeID,
		},
		Cooldown: exitAlertCooldown,
	})
	st.reachable = true
	st.upStreak = 0
	b.saveExitAlertState(ctx, st)
}

func (b *Bot) initExitAlertState(ctx context.Context, st *exitAlertState, activeID string) {
	st.initialized = true
	st.activeID = activeID
	st.reachable = true
	if b.alertsTele == nil || activeID == "" {
		return
	}
	persisted, ok, err := b.alertsTele.GetAlertState(ctx, exitHealthStateKey(activeID))
	if err != nil {
		b.log.Warn("alerts: read exit health state failed", "exit_id", activeID, "err", err)
		return
	}
	if !ok {
		return
	}
	st.reachable = persisted.Status != "down"
	st.downStreak = persisted.ConsecutiveFailures
	st.upStreak = persisted.ConsecutiveSuccesses
}

func (b *Bot) saveExitAlertState(ctx context.Context, st *exitAlertState) {
	if b.alertsTele == nil || st.activeID == "" {
		return
	}
	status := "up"
	severity := alertSeverityInfo
	if !st.reachable {
		status = "down"
		severity = alertSeverityCritical
	}
	if err := b.alertsTele.UpsertAlertState(ctx, db.AlertState{
		DedupeKey:            exitHealthStateKey(st.activeID),
		Type:                 "exit_health",
		Severity:             severity,
		Channel:              alertChannelMiniApp,
		Status:               status,
		ConsecutiveFailures:  st.downStreak,
		ConsecutiveSuccesses: st.upStreak,
		LastPayload: map[string]any{
			"exit_id":   st.activeID,
			"reachable": st.reachable,
		},
	}); err != nil {
		b.log.Warn("alerts: save exit health state failed", "exit_id", st.activeID, "err", err)
	}
}

func exitHealthStateKey(exitID string) string {
	return exitHealthStatePrefix + exitID
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
		b.emitAlert(ctx, alertEvent{
			DedupeKey: "traffic_spike:" + r.UserUUID,
			Type:      "traffic_spike",
			Severity:  alertSeverityWarning,
			Channel:   alertChannelMiniApp,
			Status:    "fired",
			Payload:   payload,
			Cooldown:  trafficSpikeCooldown,
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
