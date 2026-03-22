package config

import (
	"encoding/json"
	"testing"

	"github.com/NikitaDmitryuk/ultra/auth"
	"github.com/NikitaDmitryuk/ultra/mimic"
)

func TestBuildBridgeDevJSON(t *testing.T) {
	spec := &Spec{
		Role:          RoleBridge,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10443,
		PublicHost:    "example.com",
		DevMode:       true,
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
