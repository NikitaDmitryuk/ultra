package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestRestoredCanonicalConfigPointsAtNewBridgeAndPreservesUnknownParameters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "install.config")
	data, err := renderCanonicalInputs(
		map[string]string{
			"BRIDGE_IP":                                   "192.0.2.10",
			"DATABASE_IP":                                 "192.0.2.40",
			"DATABASE_DUMP":                               "/missing/operator-only.dump",
			"PUBLIC_HOST":                                 "edge.example.com",
			"SUBSCRIPTION_DOMAIN":                         "sync.example.com",
			"ULTRA_AUTOMATION_BRIDGE_URL":                 "https://sync.example.com/healthz",
			"ULTRA_AUTOMATION_STATIC_NODES":               `[{"name":"primary","address":"192.0.2.20","provider":"fixture"}]`,
			"ULTRA_AUTOMATION_ADMIN_TELEGRAM_ID":          "123",
			"ULTRA_AUTO_UPGRADE_MINISIGN_PUBLIC_KEY_FILE": "/etc/ultra-ansible/old-key.pub",
			"CUSTOM_PARAMETER":                            "a quoted \"value\" # suffix",
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = rewriteDeploymentConfig(path, path, "192.0.2.10", "192.0.2.20", "192.0.2.20", "edge.example.com", "sync.example.com", "provider-b", "192.0.2.50"); err != nil {
		t.Fatal(err)
	}
	p, err := installplan.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Bridge.Address != "192.0.2.20" || p.Bridge.SSHHost != "192.0.2.20" || p.Database.PrimaryHost != "192.0.2.50" ||
		p.SourceValues["CUSTOM_PARAMETER"] != "a quoted \"value\" # suffix" {
		t.Fatal("restored automatic deployment refers to old bridge or lost parameters")
	}
	values := p.SourceValues
	if _, exists := values["ULTRA_AUTO_UPGRADE_MINISIGN_PUBLIC_KEY_FILE"]; exists {
		t.Fatal("obsolete automatic channel policy survived restore")
	}
	if values["ULTRA_AUTOMATION_BRIDGE_IPV4"] != "" || values["ULTRA_AUTOMATION_BRIDGE_PROVIDER"] != "provider-b" {
		t.Fatal("recovery primary identity not rewritten")
	}
}
