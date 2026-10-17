package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestCutoverCanonicalDeltaPreservesLegacyBackendAndIsRepeatable(t *testing.T) {
	file := filepath.Join(t.TempDir(), "install.config")
	original := "ULTRA_AUTOMATION_STATIC_NODES=[{\"name\":\"primary\",\"address\":\"192.0.2.2\",\"provider\":\"fixture\"}]\nULTRA_AUTOMATION_ADMIN_TELEGRAM_ID=123\n# keep ownership policy\nBOT_DOMAIN=old.example.com\nBOT_INGRESS_IP=192.0.2.2\nPUBLIC_HOST=192.0.2.1\nVLESS_PORT=24443\n"
	if err := os.WriteFile(file, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	delta := cutoverDelta("sync.example.com", "edge.example.com", "example.com", "dial.example.net")
	if delta["PUBLIC_HOST"] != "dial.example.net" || delta["VPN_DOMAIN"] != "edge.example.com" {
		t.Fatal("cutover collapsed the public dial host into the VPN TLS identity")
	}
	if err := writeCutoverConfig(file, delta); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(file)
	if err := writeCutoverConfig(file, delta); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(file)
	if string(first) != string(second) {
		t.Fatal("non-idempotent canonical delta")
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0644 {
		t.Fatalf("canonical config mode changed: %v %v", info, err)
	}
	backup, _ := os.ReadFile(file + ".before-domain-cutover")
	if string(backup) != original {
		t.Fatal("lost canonical before image")
	}
	p, err := installplan.LoadLegacyEnvConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	if p.SchemaVersion != installplan.CurrentSchemaVersion || p.Bot.Domain != "old.example.com" ||
		p.PublicSubscriptionDomain() != "sync.example.com" {
		t.Fatal("schema 2 mapping or old TLS domain changed")
	}
	if !strings.Contains(string(first), "BOT_INGRESS_IP=192.0.2.2") || !strings.Contains(string(first), "PUBLIC_HOST=dial.example.net") {
		t.Fatal("missing compatibility policy")
	}
}

func TestParseCutoverPollIgnoresLoginNoise(t *testing.T) {
	unit, phase := parseCutoverPoll("{}\nULTRA_UNIT=activating\nwarning\nULTRA_PHASE=aliases\n")
	if unit != "activating" || phase != "aliases" {
		t.Fatalf("unexpected poll result %q %q", unit, phase)
	}
	unit, phase = parseCutoverPoll("ULTRA_PHASE=complete\nULTRA_UNIT=unknown\n")
	if unit != "unknown" || phase != "complete" {
		t.Fatalf("completion receipt lost %q %q", unit, phase)
	}
}

func TestDomainCutoverUsesSharedVultrAPIKey(t *testing.T) {
	url := "https://sync.example.com/sub/fixture-token"
	key := "fixture-provider-key"
	gotURL, gotKey, err := domainCutoverProbeInputs(map[string]string{
		"ULTRA_SUBSCRIPTION_PROBE_URL": url,
		"ULTRA_VULTR_API_KEY":          key,
	})
	if err != nil || gotURL != url || gotKey != key {
		t.Fatalf("shared probe inputs = (%q, %q, %v)", gotURL, gotKey, err)
	}
	if _, _, err = domainCutoverProbeInputs(map[string]string{
		"ULTRA_CUTOVER_SUBSCRIPTION_URL": url,
		"ULTRA_VULTR_API_KEY":            key,
	}); err == nil {
		t.Fatal("legacy cutover URL was unexpectedly accepted")
	}
}

func TestDomainCutoverRejectsMissingProbeInputsBeforeStateChanges(t *testing.T) {
	for name, raw := range map[string]string{
		"missing URL": "ULTRA_VULTR_API_KEY=fixture-provider-key\n",
		"missing key": "ULTRA_SUBSCRIPTION_PROBE_URL=https://sync.example.com/sub/fixture-token\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			env := filepath.Join(root, ".env")
			if err := os.WriteFile(env, []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(root, "state")
			t.Setenv("ULTRA_INSTALL_STATE_DIR", state)
			p := &installplan.InstallPlan{
				Bridge:  installplan.BridgeConfig{Address: "192.0.2.1", SSHHost: "fixture.example.com"},
				Secrets: installplan.SecretsConfig{EnvFile: env},
			}
			err := applyDomainCutover(
				p,
				filepath.Join(root, "install.config"),
				"sync.example.com",
				"edge.example.com",
				"example.com",
				filepath.Join(root, "receipt.json"),
				filepath.Join(root, "known_hosts"),
				"ops@example.com",
			)
			if err == nil || !strings.Contains(err.Error(), "canonical") {
				t.Fatalf("missing probe input error = %v", err)
			}
			if _, statErr := os.Stat(state); !os.IsNotExist(statErr) {
				t.Fatalf("cutover created state before validating probe inputs: %v", statErr)
			}
		})
	}
}
