package config

import (
	"encoding/json"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

func TestGRPCSelfSignedUsesPinnedPeerCertSha256(t *testing.T) {
	const pin = "e8e2d387fdbffeb38e9c9065cf30a97ee23c0e3d32ee6f78ffae40966befccc9"
	spec := &Spec{
		Role:                 RoleBridge,
		ListenAddress:        "127.0.0.1",
		VLESSPort:            443,
		PublicHost:           "example.com",
		DevMode:              true,
		SplitRouting:         BoolPtr(false),
		TunnelTransport:      TunnelTransportGRPC,
		TunnelTLSProvision:   TunnelTLSSelfSigned,
		SplithttpPath:        "/relay/v1/tunnel",
		SplitHTTPTLS:         SplitHTTPTLSSpec{ServerName: "store.steampowered.com", Alpn: []string{"h2"}, Fingerprint: "chrome"},
		SplithttpHost:        "store.steampowered.com",
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
