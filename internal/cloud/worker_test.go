package cloud

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type workerReadinessError struct{ code string }

func (e workerReadinessError) Error() string         { return "sensitive-token-value" }
func (e workerReadinessError) ReadinessCode() string { return e.code }

type workerLogHandler struct {
	inner    slog.Handler
	recovery chan struct{}
}

func (h *workerLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}
func (h *workerLogHandler) Handle(ctx context.Context, record slog.Record) error {
	if record.Message == "cloud worker recovered" {
		select {
		case h.recovery <- struct{}{}:
		default:
		}
	}
	return h.inner.Handle(ctx, record)
}
func (h *workerLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &workerLogHandler{inner: h.inner.WithAttrs(attrs), recovery: h.recovery}
}
func (h *workerLogHandler) WithGroup(name string) slog.Handler {
	return &workerLogHandler{inner: h.inner.WithGroup(name), recovery: h.recovery}
}

func TestServiceRunLogsChangedWorkerErrorsOnceAndRecovery(t *testing.T) {
	s, _, _ := testService()
	var output bytes.Buffer
	recovered := make(chan struct{}, 1)
	s.Log = slog.New(&workerLogHandler{
		inner:    slog.NewTextHandler(&output, nil),
		recovery: recovered,
	})

	var calls atomic.Int32
	s.TopologyReady = func(context.Context) error {
		switch calls.Add(1) {
		case 1, 2:
			return workerReadinessError{code: "lifecycle_busy"}
		case 3:
			return workerReadinessError{code: "controller_unavailable"}
		default:
			return nil
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.run(ctx, time.Millisecond)
		close(done)
	}()

	select {
	case <-recovered:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("worker did not report recovery")
	}
	cancel()
	<-done

	logs := output.String()
	if got := strings.Count(logs, `msg="cloud worker step failed"`); got != 2 {
		t.Fatalf("failure log count = %d, want one per changed error code; logs: %s", got, logs)
	}
	if got := strings.Count(logs, `msg="cloud worker recovered"`); got != 1 {
		t.Fatalf("recovery log count = %d, want 1; logs: %s", got, logs)
	}
	if !strings.Contains(logs, "code=lifecycle_busy") || !strings.Contains(logs, "code=controller_unavailable") {
		t.Fatalf("logs omit fixed error code: %s", logs)
	}
	if strings.Contains(logs, "sensitive-token-value") {
		t.Fatalf("logs contain raw error text: %s", logs)
	}
}

func TestServiceRunDoesNotLogShutdownCancellation(t *testing.T) {
	s, _, _ := testService()
	var output bytes.Buffer
	s.Log = slog.New(slog.NewTextHandler(&output, nil))
	entered := make(chan struct{}, 1)
	s.TopologyReady = func(ctx context.Context) error {
		entered <- struct{}{}
		<-ctx.Done()
		return errors.Join(errors.New("sensitive-token-value"), ctx.Err())
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.run(ctx, time.Millisecond)
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("worker did not begin a step")
	}
	cancel()
	<-done
	if got := output.String(); got != "" {
		t.Fatalf("shutdown emitted worker error logs: %s", got)
	}
}
