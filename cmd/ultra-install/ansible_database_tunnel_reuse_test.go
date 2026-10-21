package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestDatabaseTunnelReuseInventoryContainsOnlyPinnedReference(t *testing.T) {
	dir := t.TempDir()
	pins := filepath.Join(dir, "known_hosts")
	path := filepath.Join(dir, "private-key")
	marker := "fixture-private-tunnel-material-must-never-be-in-release"
	for name, content := range map[string]string{pins: "fixture", path: marker} {
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	p := installplan.LegacyValuesToPlan(map[string]string{
		"BRIDGE_IP": "192.0.2.1", "MAIN_EXIT_IP": "192.0.2.2", "DATABASE_IP": "192.0.2.40",
		"BRIDGE_SSH_KEY": "/keys/bridge", "MAIN_EXIT_SSH_KEY": "/keys/exit", "DATABASE_SSH_KEY": "/keys/db",
		"DB_TUNNEL_PRIVATE_KEY_FILE": path,
	})
	completeDeploymentFixture(p, "/release", pins)
	var err error
	p.Secrets.DatabaseTunnelPrivateKeySHA256, err = installplan.DatabaseTunnelPrivateKeyDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := bootstrapInventory(p, dir)
	if err != nil {
		t.Fatal(err)
	}
	vars := inv["all"].(map[string]any)["vars"].(map[string]any)
	if vars["ultra_db_tunnel_private_key_source"] != path ||
		vars["ultra_db_tunnel_private_key_sha256"] != p.Secrets.DatabaseTunnelPrivateKeySHA256 {
		t.Fatal("source identity not pinned")
	}
	raw, err := json.Marshal(inv)
	if err != nil || strings.Contains(string(raw), marker) {
		t.Fatal("private material rendered in inventory")
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = bootstrapInventory(p, dir); err == nil {
		t.Fatal("replaced private identity accepted")
	}
	p.Secrets.DatabaseTunnelPrivateKeyFile = ""
	p.Secrets.DatabaseTunnelPrivateKeySHA256 = ""
	inv, err = bootstrapInventory(p, dir)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(inv)
	if strings.Contains(string(raw), "ultra_db_tunnel_private_key") {
		t.Fatal("default bootstrap selected reuse")
	}
}
