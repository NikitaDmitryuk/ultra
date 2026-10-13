package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestAutomationReleasePreflightRejectsIncompleteAndModified(t *testing.T) {
	dir := t.TempDir()
	p := installplan.LegacyValuesToPlan(map[string]string{"BRIDGE": "192.0.2.1", "EXIT": "192.0.2.2", "REALITY_DEST": "example.com:443"})
	p.Bridge.ReuseSpec = true
	p.Automation = &installplan.AutomationConfig{ReleaseDir: dir, Version: "v1.2.3", AgeRecipient: "age1test", BridgeProvider: "a", BridgeIPv4: "192.0.2.1", BridgeURL: "https://example.com/happ", KnownHostsFile: "/pins", StaticNodes: []installplan.AutomationNode{{Name: "NL", Address: "192.0.2.2", Provider: "a"}}}
	names := []string{"ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-amd64", "ultra-bot-linux-arm64", "ultra-client-linux-amd64", "ultra-client-linux-arm64", "ultra-recovery.tar.gz"}
	var assets []map[string]any
	for _, name := range names {
		data := []byte(name)
		sum := sha256.Sum256(data)
		assets = append(assets, map[string]any{"name": name, "size": len(data), "sha256": hex.EncodeToString(sum[:])})
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	manifest := map[string]any{"version": "v1.2.3", "capabilities": []string{"service-access-v1"}, "assets": assets}
	write := func() {
		raw, _ := json.Marshal(manifest)
		if err := os.WriteFile(filepath.Join(dir, "release-manifest.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if err := preflightAutomation(p); err != nil {
		t.Fatal(err)
	}
	manifest["assets"] = assets[:len(assets)-1]
	write()
	if preflightAutomation(p) == nil {
		t.Fatal("partial release accepted")
	}
	manifest["assets"] = assets
	write()
	if err := os.WriteFile(filepath.Join(dir, names[0]), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if preflightAutomation(p) == nil {
		t.Fatal("modified binary accepted")
	}
}

func TestAutomationPollAndDurableNames(t *testing.T) {
	state := parseAutomationPoll("noise\nULTRA_UNIT=activating\nULTRA_VERSION=v2.4.1\nULTRA_READY=true\nULTRA_PENDING=false\nULTRA_ERROR=absent\n")
	if state.Unit != "activating" || state.Version != "v2.4.1" || !state.Ready || state.Pending || state.Error != "absent" {
		t.Fatalf("unexpected poll state: %#v", state)
	}
	unit, err := automationUnitName("upgrade", "v2.4.1-rc.1")
	if err != nil || unit != "ultra-automation-upgrade-v2-4-1-rc-1" {
		t.Fatalf("unexpected unit: %q %v", unit, err)
	}
	if _, err = automationUnitName("upgrade", "latest"); err == nil {
		t.Fatal("latest accepted as immutable version")
	}
	if _, err = automationBundlePath("v2.4.1;reboot"); err == nil {
		t.Fatal("unsafe version accepted")
	}
	command := durableAutomationLaunchCommand("upgrade", "/var/lib/ultra-automation/releases/v2.4.1", unit, automationTimeout(300))
	for _, required := range []string{"active|activating", "systemd-run --no-block --collect", "TimeoutStartSec=900", "/var/lib/ultra-automation/releases/v2.4.1/automation.py"} {
		if !strings.Contains(command, required) {
			t.Fatalf("durable launch misses %q: %s", required, command)
		}
	}
}

func TestAutomationTimeoutIncludesOperationMargin(t *testing.T) {
	if got := automationTimeout(300).Seconds(); got != 900 {
		t.Fatalf("timeout=%v", got)
	}
	if got := automationTimeout(0).Seconds(); got != 1500 {
		t.Fatalf("default timeout=%v", got)
	}
}

func TestPersistedAutomationStatusUsesReadyReleaseBundle(t *testing.T) {
	state := t.TempDir()
	bundle := filepath.Join(state, "releases", "v2.4.1")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "release.json"), []byte(`{"version":"v2.4.1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	script := "import sys\nraise SystemExit(0 if sys.argv[1:] == ['--action', 'status'] else 9)\n"
	if err := os.WriteFile(filepath.Join(bundle, "automation.py"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("bash", "-lc", persistedAutomationStatusCommand(state))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("persisted status failed: %v: %s", err, output)
	}
	if err := os.WriteFile(filepath.Join(state, "release.json"), []byte(`{"version":"../../tmp"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("bash", "-lc", persistedAutomationStatusCommand(state)).Run(); err == nil {
		t.Fatal("unsafe persisted version accepted")
	}
}
