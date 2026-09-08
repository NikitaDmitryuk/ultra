package config

import (
	"bytes"
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/xtls/xray-core/core"
	"testing"
)

func TestWARPDestinationBypassKeepsDefaultProxy(t *testing.T) {
	cert, key := testCertificate(t)
	spec := &Spec{Role: RoleExit, ListenAddress: "127.0.0.1", VLESSPort: 12345, Exit: ExitTunnelSpec{TunnelUUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee"}, ExitCertPaths: CertPaths{CertFile: cert, KeyFile: key}, AntiCensor: &AntiCensorSpec{WARPProxy: true, WARPDirectDomains: []string{"control.example"}}}
	strat, _ := mimic.New("steamlike")
	data, err := BuildExitXRayJSON(spec, strat, "none")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := core.LoadConfig("json", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	rules := cfg["routing"].(map[string]any)["rules"].([]any)
	first := rules[0].(map[string]any)
	if first["domain"].([]any)[0] != "full:control.example" || first["outboundTag"] != "warp-bypass" {
		t.Fatal("bypass is not restricted to exact domain")
	}
	last := rules[len(rules)-1].(map[string]any)
	if last["network"] != "tcp" || last["outboundTag"] != "direct" {
		t.Fatal("default WARP route changed")
	}
	out := cfg["outbounds"].([]any)[0].(map[string]any)
	if out["protocol"] != "socks" {
		t.Fatal("default outbound bypasses WARP")
	}
}
