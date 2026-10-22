package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
		{"destination": "/opt/ultra-recovery/ssh_policy.json", "sha256": digestSHA256([]byte("policy"))},
		{"destination": "/opt/ultra-recovery/other.json", "sha256": digestSHA256([]byte("arbitrary-json"))},
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
	if json.Unmarshal(raw, &inventory) != nil || inventory.Manifest != digestSHA256(manifest) || len(inventory.Members) != 3 ||
		inventory.Members["ultra-monitor.service"] != tools[1]["sha256"] ||
		inventory.Members["ssh_policy.json"] != tools[2]["sha256"] || inventory.Members["other.json"] != "" {
		t.Fatal(string(raw))
	}
	if _, err = upgradeLiveToolsIdentity(stage, release, digestSHA256(manifest), tools, map[string]string{"tools-manifest.json": digestSHA256(manifest)}); err == nil {
		t.Fatal("partial current tools identity accepted")
	}
}

func TestRecoveryRefreshWhitelistAllowsOnlyNamedPolicyJSON(t *testing.T) {
	contents, err := os.ReadFile(filepath.Join("..", "..", "deploy", "ansible", "roles", "recovery", "tasks", "refresh.yml"))
	if err != nil {
		t.Fatal(err)
	}
	assertion := strings.SplitN(string(contents), "item.destination is match((", 2)
	if len(assertion) != 2 {
		t.Fatal("recovery refresh destination assertion not found")
	}
	expression := strings.SplitN(assertion[1], "| regex_replace", 2)[0]
	quoted := regexp.MustCompile(`'([^']*)'`).FindAllStringSubmatch(expression, -1)
	if len(quoted) == 0 {
		t.Fatal("recovery refresh destination expression not found")
	}
	pattern := ""
	for _, part := range quoted {
		pattern += part[1]
	}
	pattern = regexp.MustCompile(`\\s+`).ReplaceAllString(pattern, "")
	whitelist, err := regexp.Compile(pattern)
	if err != nil {
		t.Fatal(err)
	}
	if !whitelist.MatchString("/opt/ultra-recovery/ssh_policy.json") {
		t.Fatal("recovery refresh whitelist rejected the named SSH policy")
	}
	if whitelist.MatchString("/opt/ultra-recovery/other.json") || whitelist.MatchString("/etc/systemd/system/ssh_policy.json") {
		t.Fatal("recovery refresh whitelist accepted arbitrary or systemd policy JSON")
	}
}

func TestRecoveryToolNameFilterAllowsOnlyNamedJSON(t *testing.T) {
	for _, name := range []string{"ssh_policy.json", "recovery.py", "ultra-monitor.service", "ultra-monitor.timer"} {
		if !isRecoveryToolName(name) {
			t.Errorf("expected %q to be a recovery tool", name)
		}
	}
	for _, name := range []string{"other.json", "ssh_policy.yaml", "test_ssh_policy.json"} {
		if isRecoveryToolName(name) {
			t.Errorf("unexpected recovery tool %q", name)
		}
	}
	if isRecoverySystemdUnit("ssh_policy.json") || !isRecoverySystemdUnit("ultra-monitor.service") {
		t.Fatal("recovery data and systemd unit suffixes were not distinguished")
	}
}
