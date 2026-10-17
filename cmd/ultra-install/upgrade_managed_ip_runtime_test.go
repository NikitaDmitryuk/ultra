package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/config"
)

func TestManagedIPRuntimePreservesIdentityAndDetectsChanges(t *testing.T) {
	s, r := runtimeHostFixture(t)
	r.Role, r.Node = config.RoleExit, ""
	r.Features.GenerateExitTLS = true
	r.Features.LogLevel = "info"
	spec := config.Spec{
		SchemaVersion: config.CurrentSpecSchemaVersion, Role: config.RoleExit,
		VLESSPort: 9443, MimicPreset: "steamlike", TunnelTransport: config.TunnelTransportGRPC,
		TunnelTLSProvision: config.TunnelTLSSelfSigned,
		Exit:               config.ExitTunnelSpec{TunnelUUID: "11111111-1111-1111-1111-111111111111"},
		ExitCertPaths:      config.CertPaths{CertFile: "/etc/ultra-relay/fullchain.pem", KeyFile: "/etc/ultra-relay/privkey.pem"},
	}
	raw, _ := json.Marshal(spec)
	if err := os.WriteFile(s.path(runtimeHostFiles[0]), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(s.path("etc/ultra-recovery")); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "fixture.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(s.path("etc/ultra-relay/fullchain.pem"), certPEM, 0600); err != nil {
		t.Fatal(err)
	}
	tunnel := sha256.Sum256([]byte(spec.Exit.TunnelUUID))
	pin := sha256.Sum256(der)
	r.Proof = &runtimeHostExitProof{
		NodeID:               "22222222-2222-2222-2222-222222222222",
		SSHHost:              "192.0.2.3",
		TopologySHA:          strings.Repeat("a", 64),
		TunnelIdentityDigest: hex.EncodeToString(tunnel[:]),
		CertificatePin:       strings.Repeat("0", 64),
	}
	r.Proof.DesiredIdentity, err = runtimeHostDesiredIdentity(r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.prepare(r); err == nil {
		t.Fatal("mismatched certificate pin accepted")
	}
	r.Proof.CertificatePin = hex.EncodeToString(pin[:])
	if _, err := s.prepare(r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transition(r.Transaction, false); err != nil {
		t.Fatal(err)
	}
	r.Transaction = "test-2"
	in := runtimeProbeInput{Request: r}
	unchanged, err := inspectRuntimeHost(s, in)
	if err != nil || unchanged.RuntimeChanged {
		t.Fatalf("unchanged managed exit: %+v %v", unchanged, err)
	}
	r.Features.LogLevel = "debug"
	in.Request = r
	changed, err := inspectRuntimeHost(s, in)
	if err != nil || !changed.RuntimeChanged {
		t.Fatalf("changed managed exit: %+v %v", changed, err)
	}
	current, err := os.ReadFile(s.path(runtimeHostFiles[0]))
	if err != nil {
		t.Fatal(err)
	}
	var after config.Spec
	if json.Unmarshal(current, &after) != nil || after.Exit.TunnelUUID != spec.Exit.TunnelUUID || after.VLESSPort != spec.VLESSPort ||
		after.TunnelTLSProvision != config.TunnelTLSSelfSigned {
		t.Fatal("managed identity changed")
	}
	retained, err := os.ReadFile(s.path("etc/ultra-relay/fullchain.pem"))
	if err != nil || string(retained) != string(certPEM) {
		t.Fatal("certificate rotated", err)
	}
}
