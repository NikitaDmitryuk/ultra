package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// Source policy is derived from the existing canonical config, never a second
// inventory. Runtime credentials are private files; signing secrets are excluded.
func prepareAutoUpgradeInputs(p *installplan.InstallPlan, directory string, variables map[string]any) error {
	if p.Automation == nil || p.Automation.AutoUpgrade == nil {
		return nil
	}
	if len(p.SourceValues) == 0 {
		return errors.New("auto_upgrade_canonical_config_required")
	}
	policy := p.Automation.AutoUpgrade
	key, err := os.ReadFile(policy.PublicKeyFile)
	if err != nil {
		return errors.New("auto_upgrade_public_key_unavailable")
	}
	if !validMinisignPublicKey(key) {
		return errors.New("auto_upgrade_public_key_invalid")
	}
	values := map[string]string{}
	for key, value := range p.SourceValues {
		if installplan.DisallowedDeploymentSecret(key) {
			return errors.New("auto_upgrade_deployment_secret_forbidden")
		}
		values[key] = value
	}
	values["IDENTITY"] = "/var/lib/ultra-relay/automation/id_ed25519"
	values["SSH_USER"] = "root"
	values["BRIDGE_SSH_HOST"] = p.Automation.BridgeIPv4
	values["ULTRA_AUTOMATION_KNOWN_HOSTS_FILE"] = "/etc/ultra-recovery/known_hosts"
	values["SECRETS_ENV_FILE"] = "/etc/ultra-ansible/.env"
	values["BOT_ENV_FILE"] = "/etc/ultra-ansible/.env"
	values["ULTRA_AUTO_UPGRADE_MINISIGN_PUBLIC_KEY_FILE"] = "/etc/ultra-ansible/release-signing.pub"
	values["ULTRA_AUTOMATION_RELEASE_DIR"] = "/opt/ultra-recovery/releases/" + p.Automation.Version
	secrets, err := installplan.ReadSecretsFile(p.SecretsEnvFile())
	if err != nil {
		return errors.New("auto_upgrade_canonical_secrets_unavailable")
	}
	runtimeSecrets := map[string]string{}
	for _, key := range []string{"TELEGRAM_BOT_TOKEN", "ULTRA_RELAY_ADMIN_TOKEN", "ULTRA_DB_DSN", "ULTRA_VULTR_API_KEY", "ULTRA_VULTR_DNS_API_KEY", "ULTRA_CUTOVER_SUBSCRIPTION_URL", "ULTRA_BOT_PUBLIC_URL", "ULTRA_BOT_TELEGRAM_SOCKS5", "ULTRA_XRAY_STATS_API"} {
		if value, ok := secrets[key]; ok {
			runtimeSecrets[key] = value
		}
	}
	files := []map[string]any{}
	for _, item := range []struct {
		name, destination string
		content           []byte
	}{
		{"release-signing.pub", "/etc/ultra-ansible/release-signing.pub", key},
	} {
		source := filepath.Join(directory, item.name)
		if err = writeUpgradeInput(source, item.content); err != nil {
			return err
		}
		files = append(files, map[string]any{"source": source, "destination": item.destination})
	}
	for name, entries := range map[string]map[string]string{"install.config": values, ".env": runtimeSecrets} {
		content, err := renderCanonicalInputs(entries)
		if err != nil {
			return err
		}
		source := filepath.Join(directory, "auto-"+strings.TrimPrefix(name, "."))
		if err = writeUpgradeInput(source, content); err != nil {
			return err
		}
		files = append(files, map[string]any{"source": source, "destination": "/etc/ultra-ansible/" + name})
	}
	variables["ultra_auto_upgrade_files"] = files
	variables["ultra_auto_upgrade_policy"] = autoUpgradePolicy{Repository: policy.Repository, PublicKeyFile: "/etc/ultra-ansible/release-signing.pub", ConfigFile: "/etc/ultra-ansible/install.config", StateDirectory: "/var/lib/ultra-ansible/downloads", OperationLockDirectory: "/var/lib/ultra-ansible", ChannelStateFile: "/var/lib/ultra-ansible/channel/state.json", CurrentManifest: "/opt/ultra-recovery/release-manifest.json", Python: "/usr/bin/python3", RequiredChecks: policy.RequiredChecks}
	variables["ultra_auto_upgrade_enabled"] = false
	return nil
}
func validMinisignPublicKey(data []byte) bool {
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(line))
		if err == nil && len(decoded) == 42 && (string(decoded[:2]) == "Ed" || string(decoded[:2]) == "ED") {
			return true
		}
	}
	return false
}
func renderCanonicalInputs(values map[string]string) ([]byte, error) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var output strings.Builder
	for _, key := range keys {
		value := values[key]
		if !regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`).MatchString(key) || strings.ContainsAny(value, "\r\n\x00") {
			return nil, errors.New("canonical_projection_value_invalid")
		}
		output.WriteString(key + "=" + strconv.Quote(value) + "\n")
	}
	return []byte(output.String()), nil
}
