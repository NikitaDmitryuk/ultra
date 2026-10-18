package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func TestAutomationStatusFailurePublishesOnlyFixedCodes(t *testing.T) {
	for _, code := range []string{
		"task_failed", "host_unreachable", "ssh_connection_refused", "ssh_authentication_failed",
		"ssh_control_path_too_long", "ssh_pin_mismatch", "ssh_temporary_directory_failed",
		"ssh_banner_timeout", "ssh_connect_timeout", "ssh_connection_reset",
	} {
		t.Run(code, func(t *testing.T) {
			diagnostic := deployansible.Diagnostic{
				Code: code, Node: "private-host.example.com", Stage: "password=private-value",
			}
			want := "automation_status_unavailable (" + code + ")"
			if got := automationStatusFailure(diagnostic).Error(); got != want {
				t.Fatalf("failure = %q; want %q", got, want)
			}
		})
	}
	for _, code := range []string{"", "password=private-value", "ssh_pin_mismatch\nprivate-payload", "unknown_failure"} {
		t.Run("reject="+code, func(t *testing.T) {
			diagnostic := deployansible.Diagnostic{
				Code: code, Node: "192.0.2.10", Stage: "route=private-route",
			}
			if got := automationStatusFailure(diagnostic).Error(); got != "automation_status_unavailable" {
				t.Fatalf("private or unknown diagnostic published: %q", got)
			}
		})
	}
}

func TestOnlyTransientSSHStatusFailuresRetry(t *testing.T) {
	for _, code := range []string{"ssh_banner_timeout", "ssh_connect_timeout", "ssh_connection_reset"} {
		if !transientAutomationStatusFailure(automationStatusFailure(deployansible.Diagnostic{Code: code})) {
			t.Errorf("%s was not retryable", code)
		}
	}
	for _, code := range []string{"ssh_pin_mismatch", "ssh_authentication_failed", "task_failed", "host_unreachable"} {
		if transientAutomationStatusFailure(automationStatusFailure(deployansible.Diagnostic{Code: code})) {
			t.Errorf("%s was retryable", code)
		}
	}
}

func TestRetryAutomationStatusBoundedAndCancelable(t *testing.T) {
	t.Run("transient then success", func(t *testing.T) {
		calls := 0
		err := retryAutomationStatus(context.Background(), func(context.Context) error {
			calls++
			if calls == 1 {
				return automationStatusFailure(deployansible.Diagnostic{Code: "ssh_banner_timeout"})
			}
			return nil
		})
		if err != nil || calls != 2 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})
	t.Run("exhaustion", func(t *testing.T) {
		calls := 0
		err := retryAutomationStatus(context.Background(), func(context.Context) error {
			calls++
			return automationStatusFailure(deployansible.Diagnostic{Code: "ssh_connection_reset"})
		})
		if err == nil || !strings.Contains(err.Error(), "ssh_connection_reset") || calls != 3 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})
	for _, code := range []string{"ssh_pin_mismatch", "ssh_authentication_failed", "unknown", "automation_not_ready"} {
		t.Run(code, func(t *testing.T) {
			calls := 0
			want := errors.New(code)
			err := retryAutomationStatus(context.Background(), func(context.Context) error { calls++; return want })
			if err != want || calls != 1 {
				t.Fatalf("err=%v calls=%d", err, calls)
			}
		})
	}
	t.Run("already canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		err := retryAutomationStatus(ctx, func(context.Context) error { calls++; return nil })
		if !errors.Is(err, context.Canceled) || calls != 0 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})
	t.Run("canceled during attempt", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		err := retryAutomationStatus(ctx, func(context.Context) error {
			calls++
			cancel()
			return automationStatusFailure(deployansible.Diagnostic{Code: "ssh_banner_timeout"})
		})
		if !errors.Is(err, context.Canceled) || calls != 1 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})
	t.Run("canceled during backoff", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		calls := 0
		go func() { time.Sleep(20 * time.Millisecond); cancel() }()
		err := retryAutomationStatus(ctx, func(context.Context) error {
			calls++
			return automationStatusFailure(deployansible.Diagnostic{Code: "ssh_banner_timeout"})
		})
		if !errors.Is(err, context.Canceled) || calls != 1 {
			t.Fatalf("err=%v calls=%d", err, calls)
		}
	})
}
