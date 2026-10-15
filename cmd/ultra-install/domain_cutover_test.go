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
	original := "# keep ownership policy\nBOT_DOMAIN=old.example.com\nBOT_INGRESS_IP=192.0.2.2\nPUBLIC_HOST=192.0.2.1\n"
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
	if p.SchemaVersion != 1 || p.Bot.Domain != "old.example.com" || p.PublicSubscriptionDomain() != "sync.example.com" {
		t.Fatal("legacy semantics or old TLS domain changed")
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

func TestDomainCutoverUsesSharedSubscriptionProbeURL(t *testing.T) {
	url := "https://sync.example.com/sub/fixture-token"
	key := "fixture-dns-key"
	gotURL, gotKey, err := domainCutoverProbeInputs(map[string]string{
		"ULTRA_SUBSCRIPTION_PROBE_URL": url,
		"ULTRA_VULTR_DNS_API_KEY":      key,
	})
	if err != nil || gotURL != url || gotKey != key {
		t.Fatalf("shared probe inputs = (%q, %q, %v)", gotURL, gotKey, err)
	}
	if _, _, err = domainCutoverProbeInputs(map[string]string{
		"ULTRA_CUTOVER_SUBSCRIPTION_URL": url,
		"ULTRA_VULTR_DNS_API_KEY":        key,
	}); err == nil {
		t.Fatal("legacy cutover URL was unexpectedly accepted")
	}
}
