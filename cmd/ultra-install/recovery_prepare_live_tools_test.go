package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLiveToolsIdentityKeepsActualPredecessorIndependentOfAppManifest(t *testing.T) {
	root := t.TempDir()
	release := filepath.Join(root, "release")
	_ = os.Mkdir(release, 0700)
	manifest := []byte(`{"version":"v0.0.2"}`)
	archive := []byte("verified-public-archive")
	_ = os.WriteFile(filepath.Join(release, "release-manifest.json"), manifest, 0600)
	_ = os.WriteFile(filepath.Join(release, "ultra-recovery.tar.gz"), archive, 0600)
	tools := []map[string]any{
		{"destination": "/opt/ultra-recovery/reconcile.py", "sha256": digestSHA256([]byte("candidate-script"))},
		{"destination": "/etc/systemd/system/ultra-monitor.service", "sha256": digestSHA256([]byte("candidate-unit"))},
	}
	stage := filepath.Join(root, "operation")
	_ = os.Mkdir(stage, 0700)
	first, err := upgradeLiveToolsIdentity(stage, release, digestSHA256(manifest), tools, nil)
	if err != nil {
		t.Fatal(err)
	}
	previous := map[string]string{}
	for _, entry := range first {
		previous[entry["name"].(string)] = entry["sha256"].(string)
	}
	second, err := upgradeLiveToolsIdentity(stage, release, digestSHA256(manifest), tools, previous)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range second {
		if entry["previous_sha256"] != entry["sha256"] {
			t.Fatal("prepared app rollback must retain actual candidate tools", entry)
		}
	}
	raw, err := os.ReadFile(filepath.Join(stage, "tools-inventory.json"))
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Manifest string            `json:"manifest_sha256"`
		Members  map[string]string `json:"members"`
	}
	if json.Unmarshal(raw, &inventory) != nil || inventory.Manifest != digestSHA256(manifest) || len(inventory.Members) != 2 ||
		inventory.Members["ultra-monitor.service"] != tools[1]["sha256"] {
		t.Fatal(string(raw))
	}
	if _, err = upgradeLiveToolsIdentity(stage, release, digestSHA256(manifest), tools, map[string]string{"tools-manifest.json": digestSHA256(manifest)}); err == nil {
		t.Fatal("partial current tools identity accepted")
	}
}
