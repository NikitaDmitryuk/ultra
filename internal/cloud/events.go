package cloud

import (
	"context"
	"log/slog"
	"time"
)

type Event struct {
	Message     string    `json:"message,omitempty"`
	OperationID string    `json:"operation_id"`
	Phase       string    `json:"phase"`
	Outcome     string    `json:"outcome"`
	Code        string    `json:"code,omitempty"`
	HTTPStatus  int       `json:"http_status,omitempty"`
	DurationMS  int64     `json:"duration_ms"`
	At          time.Time `json:"at"`
}

func (s *Service) advanceLogged(ctx context.Context, op Operation) error {
	start := s.now()
	event := Event{OperationID: op.ID, Phase: op.Phase, Outcome: "started", At: start}
	// Reconciliation may wait indefinitely; don't fill the journal with identical polls.
	report := op.State != "unknown"
	if report {
		if e := s.Store.RecordEvent(ctx, event); e != nil {
			return e
		}
	}
	log := s.Log
	if log == nil {
		log = slog.Default()
	}
	if report {
		log.Info("cloud operation stage started", "operation_id", op.ID, "phase", op.Phase, "region", op.Offer.Region.ID, "plan", op.Offer.Plan.ID)
	}
	err := s.advance(ctx, op)
	end, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	updated, readErr := s.Store.Get(end, op.ID)
	if !report && readErr == nil && updated.State == op.State && updated.Error == op.Error {
		return err
	}
	event.At = s.now()
	event.DurationMS = event.At.Sub(start).Milliseconds()
	event.Outcome = "completed"
	if err != nil {
		event.Outcome = "failed"
		event.Code = ErrorCode(err)
	}
	if readErr == nil {
		event.Code = updated.Error
		event.HTTPStatus = updated.HTTPStatus
		if err == nil && updated.Phase == op.Phase {
			event.Outcome = "waiting"
		}
	}
	saved := s.Store.RecordEvent(end, event) == nil
	level := slog.LevelInfo
	if event.Outcome == "failed" {
		level = slog.LevelWarn
	}
	log.Log(end, level, "cloud operation stage finished", "operation_id", op.ID, "phase", op.Phase, "outcome", event.Outcome, "error_code", event.Code, "http_status", event.HTTPStatus, "duration_ms", event.DurationMS, "journal_saved", saved)
	return err
}
