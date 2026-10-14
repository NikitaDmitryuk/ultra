package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestBootstrapRetryRetainsGeneratedIdentities(t *testing.T) {
	directory := t.TempDir()
	binary := filepath.Join(directory, "relay")
	if err := os.WriteFile(binary, []byte("pinned-test-artifact"), 0600); err != nil {
		t.Fatal(err)
	}
	plan := func() *installplan.InstallPlan {
		p := installplan.LegacyValuesToPlan(map[string]string{"BRIDGE": "192.0.2.1", "EXIT": "192.0.2.2", "REALITY_DEST": "example.com:443", "REUSE_BRIDGE_SPEC": "false", "DB_ENABLE": "true", "SKIP_GEO_DOWNLOAD": "true"})
		p.Artifacts.RelayBinary = binary
		return p
	}
	inventory := func() map[string]any {
		return map[string]any{"all": map[string]any{"vars": map[string]any{}, "children": map[string]any{"bridge": map[string]any{"hosts": map[string]any{"bridge": map[string]any{}}}, "exits": map[string]any{"hosts": map[string]any{"exit_0": map[string]any{}}}}}}
	}
	inspection := map[string]bootstrapInspection{"bridge": {Architecture: "amd64"}, "exit_0": {Architecture: "amd64"}}
	first, err := freezeBootstrapInventory(plan(), inventory(), inspection, directory)
	if err != nil {
		t.Fatal(err)
	}
	partialInspection := map[string]bootstrapInspection{}
	for alias, value := range inspection {
		partialInspection[alias] = value
	}
	rawPartial, _ := json.Marshal(map[string]any{"architecture": "amd64", "files": []map[string]string{{"source": "/etc/ultra-relay/spec.json", "content": base64.StdEncoding.EncodeToString([]byte(`{"role":"bridge"}`))}}})
	var partial bootstrapInspection
	if err = json.Unmarshal(rawPartial, &partial); err != nil {
		t.Fatal(err)
	}
	partialInspection["bridge"] = partial // spec installed, environment not installed before crash
	retry, err := freezeBootstrapInventory(plan(), inventory(), partialInspection, directory)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(retry)
	if string(a) != string(b) {
		t.Fatal("retry changed generated relay, route or database identity")
	}
	info, err := os.Stat(filepath.Join(directory, "inventory.frozen.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("frozen secrets are not private")
	}
}

func TestBootstrapStateRejectsForeignOrPublicDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "public")
	if err := os.Mkdir(directory, 0755); err != nil {
		t.Fatal(err)
	}
	if ensurePrivateBootstrapDirectory(directory) == nil {
		t.Fatal("public state accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(directory, link); err != nil {
		t.Fatal(err)
	}
	if ensurePrivateBootstrapDirectory(link) == nil {
		t.Fatal("symlink state accepted")
	}
}

func TestBootstrapAttemptFreshAfterTotalSuccess(t *testing.T) {
	root := t.TempDir()
	first, err := beginBootstrapAttempt(root)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := beginBootstrapAttempt(root)
	if err != nil {
		t.Fatal(err)
	}
	if retry != first {
		t.Fatal("unfinished bootstrap did not resume original attempt")
	}
	if err = completeBootstrapAttempt(root, first); err != nil {
		t.Fatal(err)
	}
	fresh, err := beginBootstrapAttempt(root)
	if err != nil {
		t.Fatal(err)
	}
	if fresh == first {
		t.Fatal("successful receipt reused instead of inspecting new invocation")
	}
	if _, err = os.Stat(first); err != nil {
		t.Fatal("prior immutable operation was deleted")
	}
}

func TestBootstrapRetainsUnrelatedRuntimeReferences(t *testing.T) {
	previous := "ULTRA_RELAY_LOG_LEVEL=warning\nULTRA_REPLICATION_KEY_FILE=/private/replication\nULTRA_RELAY_ADMIN_TOKEN=old\n"
	desired := "ULTRA_RELAY_ADMIN_TOKEN=retained\nULTRA_RELAY_LOG_LEVEL=info\n"
	merged := mergeBootstrapEnvironment(previous, desired)
	if merged != "ULTRA_REPLICATION_KEY_FILE=/private/replication\n"+desired {
		t.Fatal("runtime references lost or owned keys duplicated")
	}
}
