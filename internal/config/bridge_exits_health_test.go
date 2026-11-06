package config

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

func TestActiveHealthSwapChangesOnlyRouting(t *testing.T) {
	strategy, _ := mimic.New("apijson")
	spec := &Spec{
		Role:          RoleBridge,
		DevMode:       true,
		ListenAddress: "127.0.0.1",
		VLESSPort:     443,
		PublicHost:    "198.51.100.1",
		SplitRouting:  BoolPtr(false),
		ExitPing:      true,
	}
	nodes := []exits.Node{
		{ID: "primary", Address: "192.0.2.1", Port: 443, TunnelUUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", Priority: 1, Enabled: true},
		{ID: "reserve", Address: "192.0.2.2", Port: 443, TunnelUUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ef", Priority: 2, Enabled: true},
	}
	build := func(active string) map[string]any {
		data, err := BuildBridgeXRayJSON(spec, nil, nodes, active, strategy, "error")
		if err != nil {
			t.Fatal(err)
		}
		var cfg map[string]any
		if err = json.Unmarshal(data, &cfg); err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	cert, key := testCertificate(t)
	for _, mode := range []string{"development", "primary-xhttp-tls"} {
		t.Run(mode, func(t *testing.T) {
			if mode == "primary-xhttp-tls" {
				spec.DevMode = false
				spec.LegacyPublicEnabled = BoolPtr(false)
				spec.PrimaryXHTTP = &PrimaryXHTTPIngress{
					Host: "example.com", BackendPort: 18443,
					PublicXHTTPTLSSpec: PublicXHTTPTLSSpec{Port: 443, ServerName: "example.com", Path: "/tunnel", Mode: "stream-up"},
				}
				spec.PublicXHTTPTLS = &PublicXHTTPTLSSpec{
					Port:            8443,
					ServerName:      "example.com",
					Path:            "/fallback",
					Mode:            "stream-up",
					CertificateFile: cert,
					KeyFile:         key,
				}
				spec.Stats = &StatsSpec{APIListen: "127.0.0.1:10085"}
				spec.Database = &DatabaseSpec{DSN: "postgres://example.invalid/test"}
			}
			before, after := build("primary"), build("reserve")
			if reflect.DeepEqual(before["routing"], after["routing"]) {
				t.Fatal("health swap did not update routes")
			}
			delete(before, "routing")
			delete(after, "routing")
			if !reflect.DeepEqual(before, after) {
				t.Fatal("health selection changed non-routing configuration")
			}
		})
	}
}
