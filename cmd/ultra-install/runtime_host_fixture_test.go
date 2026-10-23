package main

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func runtimeHostFixture(t *testing.T) (runtimeHostStore, runtimeHostRequest) {
	t.Helper()
	s := runtimeHostStore{root: t.TempDir()}
	for _, dir := range []string{"etc/ultra-relay", runtimeHostStateDir} {
		if err := os.MkdirAll(s.path(dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	r := runtimeHostRequest{
		Transaction: "test-1",
		Role:        config.RoleBridge,
		Bridge:      installplan.BridgeConfig{Address: "192.0.2.1", SSHHost: "192.0.2.1", VLESSPort: 7443, RealityDest: "example.com:443"},
		Exits:       []runtimeHostExit{{Name: "primary", SSHHost: "192.0.2.2", DialAddr: "exit.example.com", Port: 9443}},
		Features:    installplan.FeatureConfig{Preset: "apijson", Transport: "grpc"},
	}
	spec := config.Spec{
		SchemaVersion: config.CurrentSpecSchemaVersion,
		GeoAssetsDir:  "/srv/ultra/geo",
		Role:          config.RoleBridge,
		MimicPreset:   "steamlike",
		VLESSPort:     7443,
		PublicHost:    "vpn.example.com",
		Reality: config.RealitySpec{
			PrivateKey:  "private-fixture",
			PublicKey:   "public-fixture",
			Dest:        "example.com:443",
			ServerNames: []string{"example.com"},
		},
		Exit:            config.ExitTunnelSpec{Address: "exit.example.com", Port: 9443, TunnelUUID: "11111111-1111-1111-1111-111111111111"},
		TunnelTransport: config.TunnelTransportGRPC,
		AntiCensor:      &config.AntiCensorSpec{DisableDOH: true, Profile: "stealth", SplitHTTPMaxChunkKB: 64},
		ExitCertPaths:   config.CertPaths{CertFile: "/etc/ultra-relay/fullchain.pem", KeyFile: "/etc/ultra-relay/privkey.pem"},
		Database:        &config.DatabaseSpec{DSN: "postgres://fixture:secret-fixture@127.0.0.1:25432/fixture"},
	}
	raw, _ := json.Marshal(spec)
	var doc map[string]json.RawMessage
	_ = json.Unmarshal(raw, &doc)
	doc["future_extension"] = json.RawMessage(`{"private":"unknown-fixture"}`)
	raw, _ = json.MarshalIndent(doc, "", "  ")
	raw = append(raw, '\n')
	if err := os.WriteFile(s.path(runtimeHostFiles[0]), raw, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.path(runtimeHostFiles[1]), []byte("# fixture\nULTRA_RELAY_ADMIN_TOKEN=secret-fixture\nOTHER=preserve\nULTRA_RELAY_LOG_LEVEL=debug\n"), 0600); err != nil {
		t.Fatal(err)
	}
	desired, err := runtimeHostDesiredIdentity(r)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := runtimeHostInstalledIdentity(raw)
	if err != nil {
		t.Fatal(err)
	}
	baseline, _ := json.Marshal(runtimeHostAttestation{desired, installed})
	if err = os.WriteFile(s.path(runtimeHostIdentityFile), baseline, 0600); err != nil {
		t.Fatal(err)
	}
	return s, r
}
