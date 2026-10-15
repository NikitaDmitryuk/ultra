package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
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
func TestRuntimeHostPrepareApplyRollbackExact(t *testing.T) {
	s, r := runtimeHostFixture(t)
	before := []runtimeHostImage{}
	for _, p := range runtimeHostFiles {
		img, err := s.image(s.path(p))
		if err != nil {
			t.Fatal(err)
		}
		before = append(before, img)
	}
	result, err := s.prepare(r)
	if err != nil || result.Status != "prepared" {
		t.Fatalf("prepare: %v %v", result, err)
	}
	for i, p := range runtimeHostFiles {
		now, _ := s.image(s.path(p))
		if !runtimeHostImagesEqual(now, before[i]) {
			t.Fatal("prepare mutated runtime")
		}
	}
	if _, err = s.transition(r.Transaction, false); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.path(runtimeHostFiles[0]))
	if err != nil {
		t.Fatal(err)
	}
	var spec config.Spec
	if json.Unmarshal(raw, &spec) != nil {
		t.Fatal("invalid candidate")
	}
	if spec.MimicPreset != "apijson" || spec.AntiCensor.DisableDOH || spec.AntiCensor.SplitHTTPMaxChunkKB != 0 {
		t.Fatal("desired settings/reset did not apply")
	}
	if !bytes.Contains(raw, []byte("unknown-fixture")) || spec.Reality.PrivateKey != "private-fixture" {
		t.Fatal("unknown fields or credentials lost")
	}
	env, _ := os.ReadFile(s.path(runtimeHostFiles[1]))
	if !bytes.Contains(env, []byte("ULTRA_RELAY_LOG_LEVEL=info")) || !bytes.Contains(env, []byte("secret-fixture")) {
		t.Fatal("environment reset/preservation failed")
	}
	out, _ := json.Marshal(result)
	if bytes.Contains(out, []byte("fixture")) {
		t.Fatal("secret in output")
	}
	if _, err = s.transition(r.Transaction, true); err != nil {
		t.Fatal(err)
	}
	for i, p := range runtimeHostFiles {
		now, _ := s.image(s.path(p))
		if !runtimeHostImagesEqual(now, before[i]) {
			t.Fatal("rollback did not restore exact bytes/metadata")
		}
	}
	if _, err = s.transition(r.Transaction, true); err != nil {
		t.Fatal("rollback is not idempotent")
	}
}
func TestRuntimeHostThirdStateBlocksAllWrites(t *testing.T) {
	s, r := runtimeHostFixture(t)
	if _, err := s.prepare(r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transition(r.Transaction, false); err != nil {
		t.Fatal(err)
	}
	specBefore, _ := os.ReadFile(s.path(runtimeHostFiles[0]))
	if err := os.WriteFile(s.path(runtimeHostFiles[1]), []byte("third-state-secret\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transition(r.Transaction, true); err == nil || err.Error() != "runtime_third_state" {
		t.Fatalf("third state: %v", err)
	}
	specAfter, _ := os.ReadFile(s.path(runtimeHostFiles[0]))
	if !bytes.Equal(specBefore, specAfter) {
		t.Fatal("rollback mutated first file before checking all files")
	}
}
func TestRuntimeHostIdentityFailsBeforeJournal(t *testing.T) {
	for _, change := range []func(*runtimeHostRequest){func(r *runtimeHostRequest) { r.Bridge.SSHHost = "192.0.2.9" }, func(r *runtimeHostRequest) { r.Exits[0].SSHHost = "192.0.2.9" }, func(r *runtimeHostRequest) { r.Database.Name = "new-db" }, func(r *runtimeHostRequest) { r.Role = config.RoleExit; r.Node = "missing" }} {
		s, r := runtimeHostFixture(t)
		before, _ := os.ReadFile(s.path(runtimeHostFiles[0]))
		change(&r)
		if _, err := s.prepare(r); err == nil || strings.Contains(err.Error(), "fixture") {
			t.Fatalf("identity mismatch: %v", err)
		}
		after, _ := os.ReadFile(s.path(runtimeHostFiles[0]))
		if !bytes.Equal(before, after) {
			t.Fatal("identity rejection mutated files")
		}
		path, _ := s.journalPath(r.Transaction)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("identity rejection created journal")
		}
	}
}
func TestRuntimeHostSymlinkFailsClosed(t *testing.T) {
	s, r := runtimeHostFixture(t)
	if err := os.Remove(s.path(runtimeHostFiles[1])); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(s.path(runtimeHostFiles[0]), s.path(runtimeHostFiles[1])); err != nil {
		t.Fatal(err)
	}
	if _, err := s.prepare(r); err == nil {
		t.Fatal("symlink accepted")
	}
}
func TestRuntimeHostIdentityCanonicalOrder(t *testing.T) {
	_, r := runtimeHostFixture(t)
	r.Exits = append(r.Exits, runtimeHostExit{Name: "other", SSHHost: "192.0.2.3", DialAddr: "other.example.com", Port: 9443})
	a, err := runtimeHostDesiredIdentity(r)
	if err != nil {
		t.Fatal(err)
	}
	r.Exits[0], r.Exits[1] = r.Exits[1], r.Exits[0]
	r.Exits[0].Port = 9444
	r.Features.LogLevel = "debug"
	b, err := runtimeHostDesiredIdentity(r)
	if err != nil || a != b {
		t.Fatal("mutable tuning/order changed identity")
	}
}

func runtimeHostLiveFixture(t *testing.T) (runtimeHostStore, runtimeHostRequest) {
	t.Helper()
	s, r := runtimeHostFixture(t)
	if err := os.Remove(s.path(runtimeHostIdentityFile)); err != nil {
		t.Fatal(err)
	}
	r.Database = installplan.DatabaseConfig{Enabled: true, Name: "fixture", User: "fixture", PrimaryHost: "192.0.2.40"}
	r.Exits[0].DialAddr = r.Exits[0].SSHHost
	img, _ := s.image(s.path(runtimeHostFiles[0]))
	var spec config.Spec
	_ = json.Unmarshal(img.Data, &spec)
	spec.Exit.Address = r.Exits[0].DialAddr
	spec.Database.DSN += "?sslmode=disable"
	raw, _ := json.Marshal(spec)
	if err := os.WriteFile(s.path(runtimeHostFiles[0]), raw, 0640); err != nil {
		t.Fatal(err)
	}
	metadata := map[string]any{
		"bridge_ipv4":     r.Bridge.Address,
		"database":        "fixture",
		"database_host":   "192.0.2.40",
		"bridge_provider": "fixture",
		"bridge_url":      "https://example.com/healthz",
		"static_nodes":    []installplan.AutomationNode{{Name: r.Exits[0].Name, Address: r.Exits[0].SSHHost, Provider: "fixture"}},
	}
	raw, _ = json.Marshal(metadata)
	for _, file := range []string{"etc/ultra-recovery/deployment.json", "etc/ultra-recovery/reconcile.json"} {
		if err := os.WriteFile(s.path(file), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return s, r
}
func TestRuntimeHostFirstManagedBridgeUpgrade(t *testing.T) {
	s, r := runtimeHostLiveFixture(t)
	if err := os.Remove(s.path(runtimeHostStateDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.prepare(r); err != nil {
		t.Fatal(err)
	}
	img, err := s.image(s.path(runtimeHostIdentityFile))
	if err != nil || !img.Exists || img.Mode != 0600 {
		t.Fatal("local attestation missing or unsafe")
	}
	if _, err := s.transition(r.Transaction, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transition(r.Transaction, true); err != nil {
		t.Fatal(err)
	}
}
func TestRuntimeHostBootstrapMigrationHasZeroWrites(t *testing.T) {
	for _, change := range []func(*runtimeHostRequest){func(r *runtimeHostRequest) { r.Exits[0].Name = "other" }, func(r *runtimeHostRequest) { r.Database.User = "other" }, func(r *runtimeHostRequest) { r.Database.PrimaryHost = "192.0.2.9" }, func(r *runtimeHostRequest) { r.Database.Name = "other" }} {
		s, r := runtimeHostLiveFixture(t)
		before, _ := os.ReadFile(s.path(runtimeHostFiles[0]))
		change(&r)
		if _, err := s.prepare(r); err == nil {
			t.Fatal("migration accepted")
		}
		after, _ := os.ReadFile(s.path(runtimeHostFiles[0]))
		if !bytes.Equal(before, after) {
			t.Fatal("runtime mutated")
		}
		for _, file := range []string{runtimeHostIdentityFile, runtimeHostStateDir + "/" + r.Transaction + ".json"} {
			if _, err := os.Stat(s.path(file)); !os.IsNotExist(err) {
				t.Fatal("rejection wrote identity or journal")
			}
		}
	}
}
func TestRuntimeHostRollbackRestoresAbsentEnvironment(t *testing.T) {
	s, r := runtimeHostFixture(t)
	r.Role = config.RoleExit
	r.Node = "primary"
	spec := config.Spec{
		SchemaVersion:   config.CurrentSpecSchemaVersion,
		Role:            config.RoleExit,
		VLESSPort:       9443,
		MimicPreset:     "steamlike",
		TunnelTransport: config.TunnelTransportGRPC,
		Exit:            config.ExitTunnelSpec{TunnelUUID: "11111111-1111-1111-1111-111111111111"},
		ExitCertPaths:   config.CertPaths{CertFile: "/etc/ultra-relay/fullchain.pem", KeyFile: "/etc/ultra-relay/privkey.pem"},
	}
	raw, _ := json.Marshal(spec)
	if err := os.WriteFile(s.path(runtimeHostFiles[0]), raw, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.path(runtimeHostFiles[1])); err != nil {
		t.Fatal(err)
	}
	desired, _ := runtimeHostDesiredIdentity(r)
	installed, _ := runtimeHostInstalledIdentity(raw)
	raw, _ = json.Marshal(runtimeHostAttestation{desired, installed})
	if err := os.WriteFile(s.path(runtimeHostIdentityFile), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.prepare(r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transition(r.Transaction, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transition(r.Transaction, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.path(runtimeHostFiles[1])); !os.IsNotExist(err) {
		t.Fatal("rollback failed to restore absence")
	}
}
func TestRuntimeHostPartialApplyRecovery(t *testing.T) {
	s, r := runtimeHostFixture(t)
	if _, err := s.prepare(r); err != nil {
		t.Fatal(err)
	}
	path, _ := s.journalPath(r.Transaction)
	saved, _ := s.image(path)
	var j runtimeHostJournal
	_ = json.Unmarshal(saved.Data, &j)
	if err := s.persist(s.path(runtimeHostFiles[0]), j.Candidate[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transition(r.Transaction, true); err != nil {
		t.Fatal(err)
	}
	now, _ := s.image(s.path(runtimeHostFiles[0]))
	if !runtimeHostImagesEqual(now, j.Before[0]) {
		t.Fatal("partial apply did not recover")
	}
}

func TestRuntimeHostFirstExitWithPinnedCallerProof(t *testing.T) {
	s, r := runtimeHostFixture(t)
	r.Role = config.RoleExit
	r.Node = "primary"
	spec := config.Spec{
		SchemaVersion:   config.CurrentSpecSchemaVersion,
		Role:            config.RoleExit,
		VLESSPort:       9443,
		MimicPreset:     "steamlike",
		TunnelTransport: config.TunnelTransportGRPC,
		Exit:            config.ExitTunnelSpec{TunnelUUID: "11111111-1111-1111-1111-111111111111"},
		ExitCertPaths:   config.CertPaths{CertFile: "/etc/ultra-relay/fullchain.pem", KeyFile: "/etc/ultra-relay/privkey.pem"},
	}
	raw, _ := json.Marshal(spec)
	if err := os.WriteFile(s.path(runtimeHostFiles[0]), raw, 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(s.path("etc/ultra-recovery")); err != nil {
		t.Fatal(err)
	}
	desired, _ := runtimeHostDesiredIdentity(r)
	sum := sha256.Sum256([]byte(spec.Exit.TunnelUUID))
	r.Proof = &runtimeHostExitProof{
		Node:                 r.Node,
		SSHHost:              r.Exits[0].SSHHost,
		DesiredIdentity:      desired,
		TunnelIdentityDigest: hex.EncodeToString(sum[:]),
	}
	bad := *r.Proof
	bad.TunnelIdentityDigest = strings.Repeat("0", 64)
	r.Proof = &bad
	if _, err := s.prepare(r); err == nil {
		t.Fatal("wrong local tunnel identity accepted")
	}
	if _, err := os.Stat(s.path("etc/ultra-recovery")); !os.IsNotExist(err) {
		t.Fatal("failed proof wrote recovery state")
	}
	bad.TunnelIdentityDigest = hex.EncodeToString(sum[:])
	if _, err := s.prepare(r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transition(r.Transaction, false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transition(r.Transaction, true); err != nil {
		t.Fatal(err)
	}
}
