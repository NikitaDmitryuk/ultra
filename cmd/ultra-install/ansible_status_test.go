package main

import (
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func TestAutomationStatusFailurePublishesOnlyFixedCodes(t *testing.T) {
	for _, code := range []string{
		"task_failed", "host_unreachable", "ssh_connection_refused", "ssh_authentication_failed",
		"ssh_control_path_too_long", "ssh_pin_mismatch", "ssh_temporary_directory_failed",
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
