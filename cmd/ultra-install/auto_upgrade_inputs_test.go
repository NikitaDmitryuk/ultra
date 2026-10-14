package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestCanonicalAutoProjectionPreservesParametersExcludesSigningSecrets(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "source.env")
	public := filepath.Join(dir, "public.key")
	publicBytes := append([]byte("Ed"), make([]byte, 40)...)
	if err := os.WriteFile(public, []byte(base64.StdEncoding.EncodeToString(publicBytes)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env, []byte("TELEGRAM_BOT_TOKEN=runtime-fixture\nMINISIGN_SECRET_KEY=must-stay-offline\nULTRA_VULTR_API_KEY=compute-fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &installplan.InstallPlan{SourceValues: map[string]string{"INSTALL_SCHEMA_VERSION": "2", "IDENTITY": "/operator/private-key", "BRIDGE": "192.0.2.1", "CUSTOM_PARAMETER": "value \"with\" # comments \\ safely"}, Secrets: installplan.SecretsConfig{EnvFile: env}, Automation: &installplan.AutomationConfig{Version: "v9.0.0", BridgeIPv4: "192.0.2.1", AutoUpgrade: &installplan.AutomationAutoUpgrade{Repository: "example/project", PublicKeyFile: public, RequiredChecks: []string{"CI"}}}}
	vars := map[string]any{}
	if err := prepareAutoUpgradeInputs(p, dir, vars); err != nil {
		t.Fatal(err)
	}
	files := vars["ultra_auto_upgrade_files"].([]map[string]any)
	for _, file := range files {
		source := file["source"].(string)
		info, err := os.Stat(source)
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("nonprivate projection")
		}
		raw, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "must-stay-offline") || strings.Contains(string(raw), "MINISIGN_SECRET_KEY") {
			t.Fatal("signing secret propagated")
		}
		if file["destination"] == "/etc/ultra-ansible/install.config" {
			values, err := installplan.ReadSecretsFile(source)
			if err != nil {
				t.Fatal(err)
			}
			if values["CUSTOM_PARAMETER"] != p.SourceValues["CUSTOM_PARAMETER"] || values["IDENTITY"] != "/var/lib/ultra-relay/automation/id_ed25519" || values["SECRETS_ENV_FILE"] != "/etc/ultra-ansible/.env" {
				t.Fatalf("parameter projection lost or local refs retained: %v", values)
			}
		}
	}
	raw, _ := json.Marshal(p)
	if strings.Contains(string(raw), "CUSTOM_PARAMETER") {
		t.Fatal("private source values serialized in public plan")
	}
	if vars["ultra_auto_upgrade_enabled"] != false {
		t.Fatal("automatic updates enabled before acceptance")
	}
	p.SourceValues["MINISIGN_SECRET_KEY"] = "wrongly-in-config"
	if prepareAutoUpgradeInputs(p, dir, map[string]any{}) == nil {
		t.Fatal("programmatic signing secret forwarded in config")
	}
}
func TestAutoProjectionRejectsPrivateSigningKeyAndMissingCanonicalInputs(t *testing.T) {
	if validMinisignPublicKey([]byte("encrypted private signing secret")) {
		t.Fatal("private key accepted as public")
	}
	p := &installplan.InstallPlan{Automation: &installplan.AutomationConfig{AutoUpgrade: &installplan.AutomationAutoUpgrade{}}}
	if prepareAutoUpgradeInputs(p, t.TempDir(), map[string]any{}) == nil {
		t.Fatal("generated second inventory accepted")
	}
}
