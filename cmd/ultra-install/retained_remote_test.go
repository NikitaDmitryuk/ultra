package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"github.com/NikitaDmitryuk/ultra/internal/operatorssh"
)

func TestRetainedMutationLostResponseIsNeverRetried(t *testing.T) {
	count := filepath.Join(t.TempDir(), "calls")
	var logs []string
	_, err := runRetainedMutationSSH(
		context.Background(),
		"database",
		[]string{"/bin/sh", "-c", `printf x >> "$1"; printf 'Connection reset by peer private-sentinel' >&2; exit 255`, "test", count},
		nil,
		func(line string) { logs = append(logs, line) },
	)
	var failure *operatorssh.Error
	if !errors.As(err, &failure) || failure.Attempts != 1 || failure.Reason != "reset" {
		t.Fatalf("unexpected mutation error: %v", err)
	}
	data, readErr := os.ReadFile(count)
	if readErr != nil || string(data) != "x" || len(logs) != 1 || !strings.Contains(logs[0], "attempt=1/1") ||
		strings.Contains(logs[0], "private-sentinel") {
		t.Fatalf("mutation retried or unsafe diagnostic: calls=%q logs=%q err=%v", data, logs, readErr)
	}
}

func TestRetainedMutationAcceptsSuccessfulReceipt(t *testing.T) {
	var logs []string
	out, err := runRetainedMutationSSH(
		context.Background(),
		"database",
		[]string{"/bin/sh", "-c", `printf '{"committed":true}'`},
		nil,
		func(line string) { logs = append(logs, line) },
	)
	if err != nil || string(out) != `{"committed":true}` || len(logs) != 1 || !strings.Contains(logs[0], "kind=success") {
		t.Fatalf("successful receipt rejected: output=%q err=%v logs=%q", out, err, logs)
	}
}

func TestRetainedRemoteLogKindsAreFixedTaxonomy(t *testing.T) {
	for input, want := range map[string]string{"ok": "success", "transient_transport": "transport", "transport_exhausted": "transport", "permanent": "permanent", "cancelled": "cancelled", "anything else": "program"} {
		if got := retainedLogKind(input); got != want {
			t.Errorf("%q => %q, want %q", input, got, want)
		}
	}
}

func TestRetainedRemoteLogReasonsAreFixedTaxonomy(t *testing.T) {
	for _, reason := range []string{"timeout", "reset", "closed", "refused", "no_route", "broken_pipe", "auth", "host_key", "unknown"} {
		if got := retainedLogReason(reason); got != reason {
			t.Errorf("%q => %q", reason, got)
		}
	}
	if got := retainedLogReason("arbitrary stderr"); got != "unknown" {
		t.Fatalf("unsafe reason escaped: %q", got)
	}
}

func TestRetainedSSHUsesSharedPolicyProfiles(t *testing.T) {
	p := &installplan.InstallPlan{
		SSH:        installplan.SSHConfig{User: "root", Identity: "/keys/operator"},
		Bridge:     installplan.BridgeConfig{SSHHost: "192.0.2.1", SSHIdentity: "/keys/operator"},
		Automation: &installplan.AutomationConfig{KnownHostsFile: "/pins/known_hosts"},
	}
	probe := strings.Join(retainedSSH(p, "192.0.2.2", "/keys/operator", false, true), " ")
	for _, option := range []string{"ConnectTimeout=15", "ServerAliveInterval=5", "ServerAliveCountMax=2", "StrictHostKeyChecking=yes", "UpdateHostKeys=no", "UserKnownHostsFile=/pins/known_hosts"} {
		if !strings.Contains(probe, option) {
			t.Errorf("probe args missing %q: %s", option, probe)
		}
	}
	mutate := strings.Join(retainedSSH(p, "192.0.2.2", "/keys/operator", false, true, "mutate"), " ")
	if !strings.Contains(mutate, "ConnectTimeout=30") {
		t.Fatalf("mutate args missing shared timeout: %s", mutate)
	}
	proxy := strings.Join(retainedSSH(p, "192.0.2.2", "/keys/operator", true, true, "mutate"), " ")
	if !strings.Contains(proxy, "ConnectTimeout=30") || !strings.Contains(proxy, "ProxyCommand=") {
		t.Fatalf("mutate proxy did not carry profile: %s", proxy)
	}
}
