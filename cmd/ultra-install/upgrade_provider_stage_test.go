package main

import (
	"strings"
	"testing"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
)

func TestUpgradeProviderStageKeepsCredentialOutOfAnsibleValues(t *testing.T) {
	tasks, err := ansibleassets.Bundle.ReadFile("roles/upgrade_provider/tasks/main.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(tasks)
	for _, required := range []string{
		"src: \"{{ ultra_upgrade_provider_key_source }}\"",
		"dest: /var/lib/ultra-relay/automation/vultr-api-key",
		"mode: \"0600\"",
		"diff: false",
		"no_log: true",
		"provider.conf.j2",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("provider stage lacks %q", required)
		}
	}

	dropin, err := ansibleassets.Bundle.ReadFile("roles/upgrade_provider/templates/provider.conf.j2")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"ULTRA_VULTR_KEY_FILE=/var/lib/ultra-relay/automation/vultr-api-key",
		"ULTRA_VULTR_SSH_KEY_FILE=/etc/ultra-fleet/id_ed25519",
		"ULTRA_VULTR_BRIDGE_IP={{ ultra_upgrade_provider_bridge_ipv4 }}",
	} {
		if !strings.Contains(string(dropin), required) {
			t.Errorf("provider drop-in lacks %q", required)
		}
	}
	if strings.Contains(string(dropin), "ULTRA_VULTR_API_KEY") {
		t.Fatal("raw API credential must never be rendered into the drop-in")
	}
	playbook, err := ansibleassets.Bundle.ReadFile("playbooks/upgrade-runtime.yml")
	if err != nil {
		t.Fatal(err)
	}
	playbookText := string(playbook)
	role := strings.Index(playbookText, "name: upgrade_provider")
	restart := strings.Index(playbookText, "name: Restart the bridge with the exact runtime image")
	if role < 0 || restart < 0 || role > restart || !strings.Contains(playbookText, "ultra_runtime_action == 'apply'") {
		t.Fatal("provider credential refresh must run on apply before the bridge relay restart")
	}
	if !strings.Contains(text, "daemon_reload: true") {
		t.Fatal("provider drop-in must be loaded into systemd before the playbook restarts the relay")
	}
}
