package config

import (
	"encoding/json"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

func TestBuildBridgeDevJSON(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10443,
		PublicHost:    "example.com",
		DevMode:       true,
		SplitRouting:  BoolPtr(false),
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBridgeXRayJSON(spec, []auth.User{{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", Name: "u"}}, s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	if root["inbounds"] == nil || root["outbounds"] == nil {
		t.Fatal(root)
	}
}

func TestBuildBridgeEmptyClients(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10444,
		PublicHost:    "example.com",
		DevMode:       true,
		SplitRouting:  BoolPtr(false),
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBridgeXRayJSON(spec, nil, s, "")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := root["inbounds"].([]any)
	if len(inbounds) < 1 {
		t.Fatal("expected inbounds")
	}
	first, _ := inbounds[0].(map[string]any)
	settings, _ := first["settings"].(map[string]any)
	clients, _ := settings["clients"].([]any)
	if clients == nil || len(clients) != 0 {
		t.Fatalf("expected empty clients, got %v", clients)
	}
}

func TestBuildClientExportDev(t *testing.T) {
	spec := &Spec{
		Role:       RoleBridge,
		VLESSPort:  443,
		PublicHost: "edge.example.com",
		DevMode:    true,
	}
	exp, err := BuildClientExport(spec, auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", Name: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if exp.VLESSURI == "" || exp.XRayOutboundJSON == nil {
		t.Fatal(exp)
	}
}

func TestBuildBridgeXRayJSONSplitUsesMphMatcher(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10445,
		PublicHost:    "example.com",
		DevMode:       true,
		SplitRouting:  BoolPtr(true),
		GeoAssetsDir:  "/nonexistent-but-unused-for-json",
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBridgeXRayJSON(spec, nil, s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	rt, _ := root["routing"].(map[string]any)
	if rt == nil {
		t.Fatal("missing routing")
	}
	if rt["domainMatcher"] != "mph" {
		t.Fatalf("domainMatcher: got %#v", rt["domainMatcher"])
	}
}

func TestBuildBridgeSOCKS5SecondInbound(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10443,
		PublicHost:    "example.com",
		DevMode:       true,
		SplitRouting:  BoolPtr(false),
		SOCKS5: &BridgeSOCKS5Spec{
			Enabled:  true,
			Port:     1080,
			Username: "dev",
			Password: "secret",
		},
		Exit: ExitTunnelSpec{
			Address:    "10.0.0.2",
			Port:       443,
			TunnelUUID: "11111111-2222-3333-4444-555555555555",
		},
	}
	s, err := mimic.New("apijson")
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildBridgeXRayJSON(spec, nil, s, "warning")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := root["inbounds"].([]any)
	if len(inbounds) != 2 {
		t.Fatalf("expected 2 inbounds, got %d", len(inbounds))
	}
	socks, _ := inbounds[1].(map[string]any)
	if socks["protocol"] != "socks" {
		t.Fatalf("second inbound: %v", socks["protocol"])
	}
}
