package main

import (
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"os"
	"path/filepath"
	"testing"
)

func TestProviderSecretsCanonicalProjection(t *testing.T) {
	d := t.TempDir()
	env := filepath.Join(d, ".env")
	if err := os.WriteFile(env, []byte("ULTRA_VULTR_API_KEY=compute-fixture\nULTRA_VULTR_DNS_API_KEY=dns-fixture\nTELEGRAM_BOT_TOKEN=bot-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &installplan.InstallPlan{Secrets: installplan.SecretsConfig{EnvFile: env}, Automation: &installplan.AutomationConfig{CloudKeyFile: "/old-compat", DNS: &installplan.AutomationDNS{Provider: "vultr"}}}
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
