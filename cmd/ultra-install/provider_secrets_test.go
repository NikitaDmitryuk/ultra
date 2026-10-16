package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestProviderSecretsCanonicalProjection(t *testing.T) {
	d := t.TempDir()
	env := filepath.Join(d, ".env")
	if err := os.WriteFile(env, []byte("ULTRA_VULTR_API_KEY=compute-fixture\nULTRA_VULTR_DNS_API_KEY=dns-fixture\nTELEGRAM_BOT_TOKEN=bot-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &installplan.InstallPlan{
		Secrets:    installplan.SecretsConfig{EnvFile: env},
		Automation: &installplan.AutomationConfig{CloudKeyFile: "/old-compat", DNS: &installplan.AutomationDNS{Provider: "vultr"}},
	}
	compute, dns, err := prepareProviderSecrets(p, d)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]string{compute: "compute-fixture", dns: "dns-fixture"} {
		b, err := os.ReadFile(path)
		if err != nil || string(b) != want {
			t.Fatal("wrong projection")
		}
		st, _ := os.Stat(path)
		if st.Mode().Perm() != 0600 {
			t.Fatal("unsafe permissions")
		}
	}
	if err := os.WriteFile(env, []byte("TELEGRAM_BOT_TOKEN=bot-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := prepareProviderSecrets(p, d); err == nil {
		t.Fatal("missing DNS key accepted")
	}
	p.Automation.DNS = nil
	compute, _, err = prepareProviderSecrets(p, d)
	if err != nil || compute != "/old-compat" {
		t.Fatal("lost file compatibility")
	}
}

func TestUpgradeProviderStageFreezesRetryCredentialAndCleansSuccess(t *testing.T) {
	root := t.TempDir()
	env := filepath.Join(root, ".env")
	if err := os.WriteFile(env, []byte("ULTRA_VULTR_API_KEY=compute-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &installplan.InstallPlan{
		Bridge:     installplan.BridgeConfig{Address: "192.0.2.10"},
		Secrets:    installplan.SecretsConfig{EnvFile: env},
		Automation: &installplan.AutomationConfig{},
	}
	operation := filepath.Join(root, "upgrade")
	source, bridge, cleanup, err := prepareUpgradeProviderStage(p, operation, 1)
	if err != nil {
		t.Fatal(err)
	}
	if bridge != p.Bridge.Address || source != filepath.Join(operation, "provider-secrets", "compute-key") {
		t.Fatal("provider stage did not bind the plan and stable operation path")
	}
	if err = os.WriteFile(env, []byte("ULTRA_VULTR_API_KEY=changed-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = prepareUpgradeProviderStage(p, operation, 1); err == nil {
		t.Fatal("changed credential accepted for a frozen upgrade retry")
	}
	staged, err := os.ReadFile(source)
	if err != nil || string(staged) != "compute-fixture" {
		t.Fatal("frozen provider credential was modified")
	}
	if err = cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Lstat(source); !os.IsNotExist(err) {
		t.Fatal("successful provider stage was not cleaned")
	}
}
