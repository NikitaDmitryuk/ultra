package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"os"
	"path/filepath"
	"testing"
)

func TestAutomationReleasePreflightRejectsIncompleteAndModified(t *testing.T) {
	dir := t.TempDir()
	p := installplan.LegacyValuesToPlan(map[string]string{"BRIDGE": "192.0.2.1", "EXIT": "192.0.2.2", "REALITY_DEST": "example.com:443"})
	p.Bridge.ReuseSpec = true
	p.Automation = &installplan.AutomationConfig{ReleaseDir: dir, Version: "v-test", AgeRecipient: "age1test", BridgeProvider: "a", BridgeIPv4: "192.0.2.1", BridgeURL: "https://example.com/happ", KnownHostsFile: "/pins", StaticNodes: []installplan.AutomationNode{{Name: "NL", Address: "192.0.2.2", Provider: "a"}}}
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
	manifest := map[string]any{"version": "v-test", "capabilities": []string{"service-access-v1"}, "assets": assets}
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
