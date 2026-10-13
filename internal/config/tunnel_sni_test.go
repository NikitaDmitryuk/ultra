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

func TestTunnelSNIAutomaticPerPinnedPeer(t *testing.T) {
	strat, _ := mimic.New("steamlike")
	const validPin = "abababababababababababababababababababababababababababababababab"
	for _, transport := range []TunnelTransport{TunnelTransportSplitHTTP, TunnelTransportGRPC} {
		for _, tc := range []struct {
			name, address, pin, mode string
			provision                TunnelTLSProvision
			omit                     bool
		}{
			{"pinned IPv4", "192.0.2.1", validPin, "", TunnelTLSSelfSigned, true},
			{"pinned IPv6", "2001:db8::1", validPin, "auto", TunnelTLSSelfSigned, true},
			{"domain", "exit.example.com", validPin, "", TunnelTLSSelfSigned, false},
			{"missing pin", "192.0.2.1", "", "", TunnelTLSSelfSigned, false},
			{"malformed pin", "192.0.2.1", "abcd", "", TunnelTLSSelfSigned, false},
			{"CA verification", "192.0.2.1", validPin, "", TunnelTLSACME, false},
			{"explicit send", "192.0.2.1", validPin, "send", TunnelTLSSelfSigned, false},
		} {
			t.Run(string(transport)+"/"+tc.name, func(t *testing.T) {
				spec := bridgeSpecForAntiCensorTest()
				spec.TunnelTransport = transport
				spec.TunnelTLSProvision = tc.provision
				spec.SplitHTTPTLS.SNIMode = tc.mode
				nodes := []exits.Node{{ID: "pinned", Address: tc.address, Port: 443, Enabled: true, PinnedPeerCertSHA256: tc.pin}, {ID: "domain", Address: "other.example.com", Port: 443, Enabled: true, PinnedPeerCertSHA256: validPin}}
				data, err := BuildBridgeXRayJSON(spec, nil, nodes, "pinned", strat, "none")
				if err != nil {
					t.Fatal(err)
				}
				var cfg map[string]any
				if err := json.Unmarshal(data, &cfg); err != nil {
					t.Fatal(err)
				}
				for _, item := range cfg["outbounds"].([]any) {
					out := item.(map[string]any)
					stream, ok := out["streamSettings"].(map[string]any)
					if !ok {
						continue
					}
					tls := stream["tlsSettings"].(map[string]any)
					omit := tc.omit && out["tag"] != exits.OutboundTag("domain")
					if (tls["serverName"] == "") != omit {
						t.Fatalf("%s: SNI omission=%t, expected %t", out["tag"], tls["serverName"] == "", omit)
					}
					if omit && tls["pinnedPeerCertSha256"] != tc.pin {
						t.Fatal("certificate authentication lost")
					}
					if tls["allowInsecure"] == true {
						t.Fatal("TLS verification disabled")
					}
				}
				if spec.SplitHTTPTLS.OmitSNI {
					t.Fatal("shared server configuration mutated")
				}
			})
		}
	}
}

func TestTunnelSNIRejectsConflictingOrUnknownMode(t *testing.T) {
	strat, _ := mimic.New("steamlike")
	for _, mode := range []string{"unknown", "send"} {
		spec := bridgeSpecForAntiCensorTest()
		spec.SplitHTTPTLS.OmitSNI = mode == "send"
		spec.SplitHTTPTLS.SNIMode = mode
		if _, err := BuildBridgeXRayJSON(spec, nil, nil, "", strat, "none"); err == nil {
			t.Fatal("invalid SNI mode accepted")
		}
	}
}
