package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapSubscriptionStageFrozenPathAndRetry(t *testing.T) {
	p, ds, inv, inspection := dependencyFixture(t)
	directory := t.TempDir()
	source := filepath.Join(t.TempDir(), "source.json")
	raw := `{"active":"v1","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`
	writeTestSubscriptionKeyring(t, source, raw)
	p.SourceValues = map[string]string{"ULTRA_SUBSCRIPTION_ENCRYPTION_KEY_FILE": source}
	if err := prepareBootstrapVariables(p, ds, inv, inspection, directory); err != nil {
		t.Fatal(err)
	}
	bridge := dependencyVars(inv, "bridge", "bridge")
	stage, ok := bridge["ultra_upgrade_subscription_key_source"].(string)
	if !ok || stage == source {
		t.Fatal("private stage path not frozen")
	}
	frozen, err := json.Marshal(inv)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(frozen), raw) || strings.Contains(string(frozen), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=") {
		t.Fatal("key material entered inventory")
	}
	info, err := os.Stat(stage)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("stage is not private", err)
	}
	cleanup, err := prepareFrozenBootstrapSubscription(p, inv, directory)
	if err != nil || cleanup == nil {
		t.Fatal("frozen bootstrap did not stage ring", err)
	}
	if err = cleanup(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(stage); !os.IsNotExist(err) {
		t.Fatal("successful bootstrap retained payload", err)
	}
	cleanup, err = prepareFrozenBootstrapSubscription(p, inv, directory)
	if err != nil {
		t.Fatal("retry could not recreate exact payload", err)
	}
	if err = cleanup(); err != nil {
		t.Fatal(err)
	}
	writeTestSubscriptionKeyring(t, source, strings.Replace(raw, "v1", "v2", -1))
	if _, err = prepareFrozenBootstrapSubscription(p, inv, directory); err == nil {
		t.Fatal("retry accepted changed ring")
	}
	delete(p.SourceValues, "ULTRA_SUBSCRIPTION_ENCRYPTION_KEY_FILE")
	if _, err = prepareFrozenBootstrapSubscription(p, inv, directory); err == nil {
		t.Fatal("retry accepted missing configured source")
	}
	bridge["ultra_upgrade_subscription_key_source"] = source
	if _, err = prepareFrozenBootstrapSubscription(p, inv, directory); err == nil {
		t.Fatal("accepted nonfrozen stage path")
	}
}

func TestBootstrapSubscriptionLegacyInputsRemainUnchanged(t *testing.T) {
	p, _, inv, _ := dependencyFixture(t)
	p.SourceValues = map[string]string{"ULTRA_SUBSCRIPTION_ENCRYPTION_KEY_FILE": "/unreadable/legacy-source"}
	before, _ := json.Marshal(inv)
	cleanup, err := prepareFrozenBootstrapSubscription(p, inv, t.TempDir())
	if err != nil || cleanup != nil {
		t.Fatal("legacy retry read newly configured source", err)
	}
	after, _ := json.Marshal(inv)
	if string(before) != string(after) {
		t.Fatal("legacy request identity changed")
	}
}

func TestBootstrapPlaybooksInstallSubscriptionBeforeRouteActivation(t *testing.T) {
	for _, name := range []string{"bootstrap.yml", "bootstrap-bridge.yml"} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("..", "..", "deploy", "ansible", "playbooks", name))
			if err != nil {
				t.Fatal(err)
			}
			text := string(raw)
			install := strings.Index(text, "name: upgrade_subscription")
			restart := strings.Index(text, "- name: Restart relay with configured subscription keyring")
			routes := strings.Index(text, "- name: Install pinned bootstrap routes")
			if install < 0 || restart < install || routes < restart {
				t.Fatal("ring and drop-in must precede restart and route activation")
			}
			delivery := text[install:routes]
			if strings.Count(delivery, "when: ultra_upgrade_subscription_key_source | default('') | length > 0") != 2 ||
				!strings.Contains(delivery, "state: restarted") {
				t.Fatal("delivery/restart must require configured source")
			}
		})
	}
}
