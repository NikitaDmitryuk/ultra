package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChannelStateSurvivesWithoutFrozenInventories(t *testing.T) {
	root := t.TempDir()
	policy := autoUpgradePolicy{OperationLockDirectory: root, StateDirectory: filepath.Join(root, "downloads")}
	identity := &channelIdentity{Version: "v9.0.0", SourceCommit: strings.Repeat("a", 40), ManifestSHA256: strings.Repeat("b", 64)}
	if err := updateChannelState(policy, identity, "pending"); err != nil {
		t.Fatal(err)
	}
	pending, err := pendingAutoUpgradeVersions(policy)
	if err != nil || len(pending) != 1 || pending[0] != identity.Version {
		t.Fatalf("restored pending skipped: %v %v", pending, err)
	}
	if err = updateChannelState(policy, identity, "activation_failed"); err != nil {
		t.Fatal(err)
	}
	pending, err = pendingAutoUpgradeVersions(policy)
	if err != nil || len(pending) != 0 {
		t.Fatalf("failed restored version retried: %v %v", pending, err)
	}
	state, err := readChannelState(channelPath(policy))
	if err != nil || state.Failed[identity.Version] != "activation_failed" {
		t.Fatal(state, err)
	}
	raw, _ := os.ReadFile(channelPath(policy))
	if strings.Contains(string(raw), "inventory") || strings.Contains(string(raw), "192.") {
		t.Fatal("topology leaked")
	}
	if updateChannelState(policy, identity, "accepted") == nil {
		t.Fatal("acceptance erased a failed block without explicit retry")
	}
	if err = os.MkdirAll(policy.StateDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	retryDirectory := filepath.Join(root, "retried-job")
	if err = os.Mkdir(retryDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if err = clearRetriedVersionMarker(context.Background(), map[string]any{"state_directory": policy.StateDirectory, "operation_lock_directory": root}, retryDirectory, identity.Version); err != nil {
		t.Fatal(err)
	}
	if err = updateChannelState(policy, identity, "accepted"); err != nil {
		t.Fatal(err)
	}
	state, err = readChannelState(channelPath(policy))
	if err != nil || state.Pending != nil || state.Accepted == nil || len(state.Failed) != 0 {
		t.Fatal(state, err)
	}
}
func TestChannelStateRejectsUnknownSecretsAndChangedPendingIdentity(t *testing.T) {
	root := t.TempDir()
	policy := autoUpgradePolicy{OperationLockDirectory: root}
	identity := &channelIdentity{Version: "v9.0.0", SourceCommit: strings.Repeat("a", 40), ManifestSHA256: strings.Repeat("b", 64)}
	if err := updateChannelState(policy, identity, "pending"); err != nil {
		t.Fatal(err)
	}
	changed := *identity
	changed.ManifestSHA256 = strings.Repeat("c", 64)
	if updateChannelState(policy, &changed, "pending") == nil {
		t.Fatal("different signed target reused pending")
	}
	var raw map[string]any
	data, _ := os.ReadFile(channelPath(policy))
	_ = json.Unmarshal(data, &raw)
	raw["inventory"] = "private"
	data, _ = json.Marshal(raw)
	_ = os.WriteFile(channelPath(policy), data, 0600)
	if _, err := readChannelState(channelPath(policy)); err == nil {
		t.Fatal("unknown state topology accepted")
	}
}

func TestNewFixedVersionPreservesFailedVersionBlock(t *testing.T) {
	policy := autoUpgradePolicy{OperationLockDirectory: t.TempDir()}
	first := &channelIdentity{Version: "v9.0.0", SourceCommit: strings.Repeat("a", 40), ManifestSHA256: strings.Repeat("b", 64)}
	if err := updateChannelState(policy, first, "pending"); err != nil {
		t.Fatal(err)
	}
	if err := updateChannelState(policy, first, "activation_failed"); err != nil {
		t.Fatal(err)
	}
	next := *first
	next.Version = "v9.0.1"
	next.ManifestSHA256 = strings.Repeat("c", 64)
	if err := updateChannelState(policy, &next, "pending"); err != nil {
		t.Fatal("fixed version blocked by failed pending", err)
	}
	state, err := readChannelState(channelPath(policy))
	if err != nil || state.Pending.Version != next.Version || state.Failed[first.Version] == "" {
		t.Fatal(state, err)
	}
}
