package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func runtimeSecretsFixture(t *testing.T) (string, uint32, uint32) {
	t.Helper()
	root := t.TempDir()
	for _, path := range []string{"etc/ultra-relay", "var/lib/ultra-relay/automation"} {
		if err := os.MkdirAll(filepath.Join(root, path), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for path, value := range map[string]string{
		"etc/ultra-relay/bot.env":                      "TELEGRAM_BOT_TOKEN=\"fixture-bot\"\nULTRA_DB_DSN=ignored\n",
		"var/lib/ultra-relay/automation/vultr-api-key": "fixture-provider",
	} {
		if err := os.WriteFile(filepath.Join(root, path), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, uint32(os.Geteuid()), uint32(os.Getegid())
}

func TestInstalledRuntimeSecretsPrivateReader(t *testing.T) {
	paths := []string{"/etc/ultra-relay/bot.env", "/var/lib/ultra-relay/automation/vultr-api-key"}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			root, uid, gid := runtimeSecretsFixture(t)
			read := func() ([]byte, error) { return readInstalledRuntimeFile(root, path, uid, gid, uid, gid) }
			if _, err := read(); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(root, path)
			original, _ := os.ReadFile(file)
			for _, mode := range []os.FileMode{0644, 0400, 0660} {
				if err := os.Chmod(file, mode); err != nil {
					t.Fatal(err)
				}
				if _, err := read(); err == nil || err.Error() != "installed_runtime_secrets_untrusted" {
					t.Fatal("unsafe mode accepted")
				}
			}
			_ = os.Chmod(file, 0600)
			if _, err := readInstalledRuntimeFile(root, path, uid+1, gid, uid, gid); err == nil {
				t.Fatal("wrong owner accepted")
			}
			if _, err := readInstalledRuntimeFile(root, path, uid, gid+1, uid, gid); err == nil {
				t.Fatal("wrong group accepted")
			}
			_ = os.WriteFile(file, []byte(strings.Repeat("x", 65537)), 0600)
			if _, err := read(); err == nil {
				t.Fatal("oversize accepted")
			}
			_ = os.WriteFile(file, original, 0600)
			_, err := readInstalledRuntimeFileChecked(root, path, uid, gid, uid, gid, func() {
				_ = os.Rename(file, file+".previous")
				_ = os.WriteFile(file, original, 0600)
			})
			if err == nil {
				t.Fatal("replaced file accepted")
			}
			_ = os.Remove(file)
			if _, err := read(); err == nil {
				t.Fatal("missing accepted")
			}
			_ = os.Symlink(file+".previous", file)
			if _, err := read(); err == nil {
				t.Fatal("symlink accepted")
			}
			_ = os.Remove(file)
			_ = os.Rename(file+".previous", file)
			parent := filepath.Dir(file)
			_ = os.Rename(parent, parent+".previous")
			_ = os.Symlink(parent+".previous", parent)
			if _, err := read(); err == nil {
				t.Fatal("ancestor symlink accepted")
			}
		})
	}
}

func TestInstalledRuntimeSecretsStateDirectoryModes(t *testing.T) {
	root, uid, gid := runtimeSecretsFixture(t)
	stateDir := filepath.Join(root, "var/lib/ultra-relay")
	keyPath := "/var/lib/ultra-relay/automation/vultr-api-key"
	read := func(relayUID, relayGID uint32) ([]byte, error) {
		return readInstalledRuntimeFile(root, keyPath, uid, gid, relayUID, relayGID)
	}
	for _, mode := range []os.FileMode{0700, 0755} {
		if err := os.Chmod(stateDir, mode); err != nil {
			t.Fatal(err)
		}
		got, err := read(uid, gid)
		if err != nil || string(got) != "fixture-provider" {
			t.Fatalf("state directory mode %04o rejected valid key read: %v", mode, err)
		}
	}
	for _, mode := range []os.FileMode{0750, 0770, 0775, 0777, os.ModeSticky | 0755, os.ModeSetgid | 0755} {
		if err := os.Chmod(stateDir, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := read(uid, gid); err == nil {
			t.Fatalf("unsafe state directory mode %v accepted", mode)
		}
	}
	if err := os.Chmod(stateDir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := read(uid+1, gid); err == nil {
		t.Fatal("wrong state directory owner accepted")
	}
	if _, err := read(uid, gid+1); err == nil {
		t.Fatal("wrong state directory group accepted")
	}
	for _, parent := range []string{"etc/ultra-relay", "var/lib/ultra-relay/automation"} {
		if err := os.Chmod(filepath.Join(root, parent), 0755); err != nil {
			t.Fatal(err)
		}
		path := "/etc/ultra-relay/bot.env"
		if strings.HasPrefix(parent, "var/") {
			path = "/var/lib/ultra-relay/automation/vultr-api-key"
		}
		if _, err := readInstalledRuntimeFile(root, path, uid, gid, uid, gid); err == nil {
			t.Fatalf("parent mode 0755 accepted for %s", parent)
		}
	}
	root, uid, gid = runtimeSecretsFixture(t)
	stateDir = filepath.Join(root, "var/lib/ultra-relay")
	previous := stateDir + ".previous"
	if err := os.Rename(stateDir, previous); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(previous, stateDir); err != nil {
		t.Fatal(err)
	}
	if _, err := readInstalledRuntimeFile(root, keyPath, uid, gid, uid, gid); err == nil {
		t.Fatal("state directory symlink accepted")
	}

	root, uid, gid = runtimeSecretsFixture(t)
	stateDir = filepath.Join(root, "var/lib/ultra-relay")
	_, err := readInstalledRuntimeFileChecked(root, keyPath, uid, gid, uid, gid, func() {
		_ = os.Rename(stateDir, stateDir+".previous")
		_ = os.Mkdir(stateDir, 0755)
		_ = os.Mkdir(filepath.Join(stateDir, "automation"), 0700)
		_ = os.WriteFile(filepath.Join(stateDir, "automation/vultr-api-key"), []byte("replacement"), 0600)
	})
	if err == nil {
		t.Fatal("replaced state directory accepted")
	}
}

func TestInstalledRuntimeSecretsMetadataPolicy(t *testing.T) {
	for _, raw := range []string{`{"secrets_source":null}`, `{"secrets_source":""}`, `{"secrets_source":true}`, `{"secrets_source":"unknown"}`} {
		var journal struct {
			Source journalSecretsSource `json:"secrets_source"`
		}
		if err := json.Unmarshal([]byte(raw), &journal); err == nil {
			t.Fatal("invalid journal selector accepted")
		}
	}
	before := syscall.Stat_t{Ino: 1, Mode: 0600, Uid: 100, Gid: 100, Size: 12}
	after := before
	after.Atim.Sec++
	if !stableRuntimeSecretStat(before, after) {
		t.Fatal("read atime rejected")
	}
	for _, change := range []func(*syscall.Stat_t){
		func(s *syscall.Stat_t) { s.Ino++ }, func(s *syscall.Stat_t) { s.Ctim.Sec++ },
		func(s *syscall.Stat_t) { s.Mtim.Sec++ }, func(s *syscall.Stat_t) { s.Uid++ },
		func(s *syscall.Stat_t) { s.Mode = 0644 },
	} {
		after = before
		change(&after)
		if stableRuntimeSecretStat(before, after) {
			t.Fatal("metadata drift accepted")
		}
	}
	plan := &installplan.InstallPlan{Automation: &installplan.AutomationConfig{
		BridgeProvider: "vultr", DNS: &installplan.AutomationDNS{Provider: "vultr"},
	}}
	for _, identity := range []struct {
		euid  int
		local bool
	}{{1000, true}, {0, false}} {
		if err := validateInstalledRuntimeSource(plan, identity.euid, identity.local); err == nil {
			t.Fatal("unconfirmed bridge accepted")
		}
	}
	if err := validateInstalledRuntimeSource(plan, 0, true); err != nil {
		t.Fatal(err)
	}
	plan.Automation.BridgeProvider = "independent-provider"
	if err := validateInstalledRuntimeSource(plan, 0, true); err != nil {
		t.Fatalf("independent bridge hosting provider rejected: %v", err)
	}
	plan.Automation.DNS.Provider = "unsupported"
	if err := validateInstalledRuntimeSource(plan, 0, true); err == nil {
		t.Fatal("unsupported DNS provider accepted")
	}
}

func TestInstalledRuntimeSecretsProjectionAndIdentity(t *testing.T) {
	root, uid, gid := runtimeSecretsFixture(t)
	p := &installplan.InstallPlan{Bot: installplan.BotConfig{Enabled: true}, Automation: &installplan.AutomationConfig{
		BridgeProvider: "independent-provider", Ingress: &installplan.AutomationIngress{}, DNS: &installplan.AutomationDNS{Provider: "vultr"},
	}, Secrets: installplan.SecretsConfig{EnvFile: filepath.Join(root, "not-staged.env")}}
	before, _ := json.Marshal(p)
	digest, _ := operatorPlanDigest(p, "release")
	p.SecretSource = installedRuntimeSecrets
	p.SecretResolver = installedRuntimeResolver(true, true, func(path string) ([]byte, error) {
		return readInstalledRuntimeFile(root, path, uid, gid, uid, gid)
	})
	after, err := json.Marshal(p)
	if err != nil || string(before) != string(after) {
		t.Fatal("serialized plan changed")
	}
	afterDigest, _ := operatorPlanDigest(p, "release")
	if digest != afterDigest {
		t.Fatal("plan digest changed")
	}
	values, err := installplan.ReadPlanSecrets(p)
	if err != nil || len(values) != 2 || values["TELEGRAM_BOT_TOKEN"] != "fixture-bot" {
		t.Fatal("incorrect allowlist projection")
	}
	values["TELEGRAM_BOT_TOKEN"] = "consumer mutation"
	values, _ = installplan.ReadPlanSecrets(p)
	if values["TELEGRAM_BOT_TOKEN"] != "fixture-bot" {
		t.Fatal("shared map changed")
	}
	bot, err := installplan.BotEnvironment(values)
	if err != nil || !strings.Contains(string(bot), "fixture-bot") || strings.Contains(string(bot), "provider") {
		t.Fatal("invalid bot projection")
	}
	stage := t.TempDir()
	compute, err := prepareComputeProviderSecret(p, stage)
	if err != nil {
		t.Fatal(err)
	}
	key, _ := os.ReadFile(compute)
	variables := map[string]any{}
	if err := prepareAnsibleDNS(p, variables); err != nil || variables["ultra_dns_api_key"] != string(key) {
		t.Fatal("provider and DNS differ")
	}
	_ = os.WriteFile(filepath.Join(root, "var/lib/ultra-relay/automation/vultr-api-key"), []byte("changed-provider"), 0600)
	if _, err := prepareComputeProviderSecret(p, stage); err == nil {
		t.Fatal("retry credential drift accepted")
	}
	if _, err := os.Stat(p.SecretsEnvFile()); !os.IsNotExist(err) {
		t.Fatal("canonical secret projection created")
	}
	canonical := &installplan.InstallPlan{Secrets: installplan.SecretsConfig{EnvFile: filepath.Join(root, "canonical.env")}}
	_ = os.WriteFile(canonical.SecretsEnvFile(), []byte("TELEGRAM_BOT_TOKEN=canonical-fixture\n"), 0600)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := installplan.ReadPlanSecrets(canonical)
			if err != nil || got["TELEGRAM_BOT_TOKEN"] != "canonical-fixture" {
				t.Error("resolver leaked to independent plan")
			}
		}()
	}
	wg.Wait()
}

func TestInstalledRuntimeSecretsSourceFreeze(t *testing.T) {
	for _, source := range []string{"canonical", installedRuntimeSecrets} {
		t.Run(source, func(t *testing.T) {
			directory := t.TempDir()
			p := &installplan.InstallPlan{SecretSource: source}
			if err := freezeOperatorPlan(directory, p, "release"); err != nil {
				t.Fatal(err)
			}
			if err := matchOperatorPlan(directory, p, "release"); err != nil {
				t.Fatal(err)
			}
			p.SecretSource = map[string]string{"canonical": installedRuntimeSecrets, installedRuntimeSecrets: "canonical"}[source]
			if err := freezeOperatorPlan(directory, p, "release"); err == nil {
				t.Fatal("source switch accepted")
			}
			if err := matchOperatorPlan(directory, p, "release"); err == nil {
				t.Fatal("completed source switch accepted")
			}
		})
	}
	directory := t.TempDir()
	p := &installplan.InstallPlan{}
	if err := freezeOperatorPlan(directory, p, "release"); err != nil {
		t.Fatal(err)
	}
	if err := freezeOperatorPlan(directory, p, "release"); err != nil {
		t.Fatal("legacy canonical rejected")
	}
	p.SecretSource = installedRuntimeSecrets
	if err := freezeOperatorPlan(directory, p, "release"); err == nil {
		t.Fatal("legacy silently reinterpreted")
	}
	if err := bindVerificationSecretsSource(p, installedRuntimeSecrets); err != nil || p.SecretResolver != nil {
		t.Fatal("verification installed resolver")
	}
	if err := bindVerificationSecretsSource(p, "unknown"); err == nil {
		t.Fatal("unknown verification source accepted")
	}
	for _, source := range []string{"unknown", "installed-runtime"} {
		hash, _ := operatorPlanDigest(&installplan.InstallPlan{}, "release")
		raw, _ := json.Marshal(map[string]string{"plan_sha256": hash, "secrets_source": source})
		_ = os.WriteFile(filepath.Join(directory, "operator-plan.json"), raw, 0600)
		if err := matchOperatorPlan(directory, &installplan.InstallPlan{}, "release"); err == nil {
			t.Fatal("changed frozen metadata accepted")
		}
	}
}

func TestInstalledRuntimeSecretsMissingInputs(t *testing.T) {
	for _, content := range []string{"", "ULTRA_DB_DSN=fixture\n", "TELEGRAM_BOT_TOKEN=\n", "TELEGRAM_BOT_TOKEN=x\nTELEGRAM_BOT_TOKEN=y\n"} {
		resolve := installedRuntimeResolver(true, false, func(string) ([]byte, error) { return []byte(content), nil })
		if _, err := resolve(); err == nil || strings.Contains(err.Error(), "fixture") {
			t.Fatal("invalid token accepted or disclosed")
		}
	}
	resolve := installedRuntimeResolver(false, true, func(string) ([]byte, error) { return []byte(""), nil })
	if _, err := resolve(); err == nil {
		t.Fatal("missing provider accepted")
	}
	for _, required := range []struct {
		bot, provider bool
		wantReads     int
	}{{false, false, 0}, {true, false, 1}, {false, true, 1}} {
		reads := 0
		resolve := installedRuntimeResolver(required.bot, required.provider, func(path string) ([]byte, error) {
			reads++
			if path == "/etc/ultra-relay/bot.env" {
				return []byte("TELEGRAM_BOT_TOKEN=fixture"), nil
			}
			return []byte("fixture-provider"), nil
		})
		if _, err := resolve(); err != nil || reads != required.wantReads {
			t.Fatal("read an unrequired secret")
		}
	}
}
