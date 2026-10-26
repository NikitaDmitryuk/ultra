package adminapi

import (
	"encoding/json"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

func TestExitDeployHintsContainMetadataWithoutInstallationCommand(t *testing.T) {
	s := &Server{spec: &config.Spec{VLESSPort: 443, SplithttpHost: "example.com", SplithttpPath: "/tunnel"}}
	raw, err := json.Marshal(s.deployHints(exits.Node{TunnelUUID: "fixture-tunnel"}))
	if err != nil {
		t.Fatal(err)
	}
	var hints map[string]any
	if err := json.Unmarshal(raw, &hints); err != nil {
		t.Fatal(err)
	}
	if _, found := hints["install_example"]; found {
		t.Fatal("API advertised a removed installation CLI")
	}
	if hints["tunnel_uuid"] != "fixture-tunnel" || hints["tunnel_port"] != float64(443) || hints["splithttp_path"] != "/tunnel" ||
		hints["splithttp_host"] != "example.com" {
		t.Fatalf("tunnel metadata changed: %s", raw)
	}
}
