package config

import (
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"strings"
	"testing"
)

func TestOmitTunnelSNIRequiresPinnedIP(t *testing.T) {
	strat, _ := mimic.New("steamlike")
	for _, tc := range []struct {
		name, address, pin string
		provision          TunnelTLSProvision
		ok                 bool
	}{
		{"pinned IP", "192.0.2.1", strings.Repeat("ab", 32), TunnelTLSSelfSigned, true},
		{"missing pin", "192.0.2.1", "", TunnelTLSSelfSigned, false},
		{"domain", "exit.example", strings.Repeat("ab", 32), TunnelTLSSelfSigned, false},
		{"CA mode", "192.0.2.1", strings.Repeat("ab", 32), TunnelTLSACME, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := bridgeSpecForAntiCensorTest()
			spec.TunnelTLSProvision = tc.provision
			spec.SplitHTTPTLS.OmitSNI = true
			node := exits.Node{ID: "1", Address: tc.address, Port: 443, Enabled: true, PinnedPeerCertSHA256: tc.pin}
			data, err := BuildBridgeXRayJSON(spec, nil, []exits.Node{node}, node.ID, strat, "none")
			if !tc.ok {
				if err == nil {
					t.Fatal("unsafe SNI omission accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var cfg map[string]any
			if err = json.Unmarshal(data, &cfg); err != nil {
				t.Fatal(err)
			}
			tls := cfg["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)
			if tls["serverName"] != "" || tls["pinnedPeerCertSha256"] != tc.pin {
				t.Fatal("SNI omitted without retaining pin")
			}
			if tls["allowInsecure"] == true {
				t.Fatal("TLS verification disabled")
			}
		})
	}
}
