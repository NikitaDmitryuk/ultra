package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

func TestBridgeMixedCATunnelAndPinnedCloudExit(t *testing.T) {
	for _, transport := range []TunnelTransport{TunnelTransportSplitHTTP, TunnelTransportGRPC} {
		t.Run(string(transport), func(t *testing.T) {
			spec := bridgeSpecForAntiCensorTest()
			spec.TunnelTLSProvision = TunnelTLSACME
			spec.TunnelTransport = transport
			spec.SplitHTTPTLS.ServerName = "tunnel.example.com"
			pin := strings.Repeat("ab", 32)
			nodes := []exits.Node{
				{ID: "static", Address: "tunnel.example.com", Port: 443, Enabled: true},
				{ID: "cloud", Address: "192.0.2.2", Port: 443, Enabled: true, PinnedPeerCertSHA256: pin},
			}
			strat, err := mimic.New("steamlike")
			if err != nil {
				t.Fatal(err)
			}
			data, err := BuildBridgeXRayJSON(spec, nil, nodes, "static", strat, "none")
			if err != nil {
				t.Fatal(err)
			}
			var rendered struct {
				Outbounds []struct {
					Tag    string `json:"tag"`
					Stream struct {
						TLS map[string]any `json:"tlsSettings"`
					} `json:"streamSettings"`
				} `json:"outbounds"`
			}
			if err := json.Unmarshal(data, &rendered); err != nil {
				t.Fatal(err)
			}
			seen := 0
			for _, outbound := range rendered.Outbounds {
				tls := outbound.Stream.TLS
				switch outbound.Tag {
				case exits.OutboundTag("cloud"):
					seen++
					if tls["serverName"] != "" || tls["pinnedPeerCertSha256"] != pin {
						t.Fatal("cloud exit lost certificate authentication", tls)
					}
				case exits.OutboundTag("static"):
					seen++
					if tls["serverName"] != "tunnel.example.com" || tls["pinnedPeerCertSha256"] != nil {
						t.Fatal("static CA policy changed", tls)
					}
				}
				if tls["allowInsecure"] != nil {
					t.Fatal("TLS verification bypassed")
				}
			}
			if seen != 2 || spec.TunnelTLSProvision != TunnelTLSACME || spec.SplitHTTPTLS.OmitSNI {
				t.Fatal("missing outbound or mutated bridge policy")
			}
		})
	}
}

func TestGRPCSelfSignedUsesPinnedPeerCertSha256(t *testing.T) {
	const pin = "e8e2d387fdbffeb38e9c9065cf30a97ee23c0e3d32ee6f78ffae40966befccc9"
	spec := &Spec{
		Role:               RoleBridge,
		ListenAddress:      "127.0.0.1",
		VLESSPort:          443,
		PublicHost:         "example.com",
		DevMode:            true,
		SplitRouting:       BoolPtr(false),
		TunnelTransport:    TunnelTransportGRPC,
		TunnelTLSProvision: TunnelTLSSelfSigned,
		SplithttpPath:      "/relay/v1/tunnel",
		SplitHTTPTLS:       SplitHTTPTLSSpec{ServerName: "store.steampowered.com", Alpn: []string{"h2"}, Fingerprint: "chrome"},
		SplithttpHost:      "store.steampowered.com",
	}
	strat, err := mimic.New("steamlike")
	if err != nil {
		t.Fatal(err)
	}
	nodes := []exits.Node{{
		ID:                   "58c7746d-4294-4300-91b2-07f2a4c515ad",
		Address:              "10.0.0.2",
		Port:                 51001,
		TunnelUUID:           "11111111-2222-3333-4444-555555555555",
		PinnedPeerCertSHA256: pin,
		Enabled:              true,
	}}
	b, err := BuildBridgeXRayJSON(spec, nil, nodes, nodes[0].ID, strat, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	outbounds, _ := root["outbounds"].([]any)
	for _, ob := range outbounds {
		m, _ := ob.(map[string]any)
		if m["tag"] != exits.OutboundTag(nodes[0].ID) {
			continue
		}
		ss, _ := m["streamSettings"].(map[string]any)
		tls, _ := ss["tlsSettings"].(map[string]any)
		if _, ok := tls["allowInsecure"]; ok {
			t.Fatal("allowInsecure must not be present")
		}
		got, _ := tls["pinnedPeerCertSha256"].(string)
		if got != pin {
			t.Fatalf("pinnedPeerCertSha256 = %q, want %q", got, pin)
		}
		return
	}
	t.Fatal("exit outbound not found")
}
