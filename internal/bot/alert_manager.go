package bot

import (
	"context"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

const (
	alertSeverityInfo     = "info"
	alertSeverityWarning  = "warning"
	alertSeverityCritical = "critical"

	alertChannelMiniApp  = "miniapp"
	alertChannelTelegram = "telegram"
)

type alertEvent struct {
	DedupeKey string
	Type      string
	Severity  string
	Channel   string
	Status    string
	Payload   map[string]any
	Cooldown  time.Duration
}

func (b *Bot) emitAlert(ctx context.Context, ev alertEvent) {
	if b.alertsTele == nil || ev.DedupeKey == "" || ev.Type == "" {
		return
	}
	if ev.Severity == "" {
		ev.Severity = alertSeverityInfo
	}
	if ev.Channel == "" {
		ev.Channel = alertChannelMiniApp
	}
	if ev.Status == "" {
		ev.Status = "open"
	}
	payload := clonePayload(ev.Payload)
	payload["dedupe_key"] = ev.DedupeKey
	payload["severity"] = ev.Severity
	payload["channel"] = ev.Channel

	st, _, err := b.alertsTele.GetAlertState(ctx, ev.DedupeKey)
	if err != nil {
		b.log.Warn("alerts: read state failed", "key", ev.DedupeKey, "err", err)
	}
	if ev.Cooldown > 0 && st.LastSentAt != nil && time.Since(*st.LastSentAt) < ev.Cooldown {
		st.Type = ev.Type
		st.Severity = ev.Severity
		st.Channel = ev.Channel
		st.Status = ev.Status
		st.LastPayload = payload
		_ = b.alertsTele.UpsertAlertState(ctx, st)
		return
	}

	admins, err := b.adminRepo.ListAdmins(ctx)
	if err != nil {
		b.log.Warn("alerts: list admins", "err", err)
		return
	}
	var sentAt *time.Time
	if ev.Channel != alertChannelTelegram {
		now := time.Now()
		sentAt = &now
	}
	for _, a := range admins {
		if err := b.alertsTele.EnqueueNotification(ctx, db.Notification{
			TelegramID: a.TelegramID,
			Type:       ev.Type,
			Payload:    payload,
			SentAt:     sentAt,
		}); err != nil {
			b.log.Warn("alerts: enqueue notification failed", "type", ev.Type, "tg_id", a.TelegramID, "err", err)
		}
	}

	now := time.Now()
	st = db.AlertState{
		DedupeKey:            ev.DedupeKey,
		Type:                 ev.Type,
		Severity:             ev.Severity,
		Channel:              ev.Channel,
		Status:               ev.Status,
		ConsecutiveFailures:  st.ConsecutiveFailures,
		ConsecutiveSuccesses: st.ConsecutiveSuccesses,
		LastSentAt:           &now,
		LastPayload:          payload,
	}
	if err := b.alertsTele.UpsertAlertState(ctx, st); err != nil {
		b.log.Warn("alerts: upsert state failed", "key", ev.DedupeKey, "err", err)
	}
}

func clonePayload(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+3)
	for k, v := range in {
		out[k] = v
	}
	return out
}
