package main

import (
	"bytes"
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
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestUpgradeInputIsPrivateImmutableAndRejectsSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "input")
	if err := writeUpgradeInput(path, []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	if err := writeUpgradeInput(path, []byte("fixture")); err != nil {
		t.Fatal(err)
	}
	if writeUpgradeInput(path, []byte("changed")) == nil {
		t.Fatal("changed frozen input accepted")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if writeUpgradeInput(path, []byte("fixture")) == nil {
		t.Fatal("public private material accepted")
	}
	symlink := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(path, symlink); err != nil {
		t.Fatal(err)
	}
	if writeUpgradeInput(symlink, []byte("fixture")) == nil {
		t.Fatal("symlinked input accepted")
	}
}

func TestRebuildInputRejectsLinksPermissionsAndSpecialFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "input")
	if err := os.WriteFile(path, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"symlink", "hardlink", "public", "fifo", "directory"} {
		t.Run(kind, func(t *testing.T) {
			candidate := filepath.Join(root, kind)
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(path, candidate)
			case "hardlink":
				err = os.Link(path, candidate)
			case "public":
				err = os.WriteFile(candidate, []byte("private"), 0644)
			case "fifo":
				err = syscall.Mkfifo(candidate, 0600)
			case "directory":
				err = os.Mkdir(candidate, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = readRebuildInput(candidate, true); err == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
}

func TestRetainedCredentialsRequireStablePrivateIdentity(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "saved.json")
	p := &installplan.InstallPlan{Database: installplan.DatabaseConfig{Name: "fixture", User: "app"}}
	if _, err := retainedExistingDatabaseCredentials(p); err == nil {
		t.Fatal("missing credentials would permit random password generation")
	}
	p.Secrets.DatabaseCredentialsFile = path
	for _, dsn := range []string{"postgres://app:fixture@127.0.0.1:25432/fixture", "postgres://wrong:fixture@127.0.0.1:25432/fixture", "postgres://app@127.0.0.1:25432/fixture", "postgres://app:fixture@192.0.2.1:5432/fixture"} {
		raw, _ := json.Marshal(map[string]any{"database": map[string]string{"dsn": dsn}})
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := retainedExistingDatabaseCredentials(p)
		if dsn == "postgres://app:fixture@127.0.0.1:25432/fixture" {
			if err != nil || got != dsn {
				t.Fatal("stable credentials rejected")
			}
		} else if err == nil {
			t.Fatal("invalid identity accepted")
		}
	}
	if err := os.WriteFile(path, []byte(`{"database":{"dsn":"postgres://app:fixture@127.0.0.1:25432/fixture"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := retainedExistingDatabaseCredentials(p); err == nil {
		t.Fatal("public credentials accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := retainedExistingDatabaseCredentials(p); err == nil {
		t.Fatal("absent saved credentials accepted")
	}
}

func TestRetainedProxyCommandPreservesPinnedArgv(t *testing.T) {
	p := &installplan.InstallPlan{
		SSH:        installplan.SSHConfig{User: "root"},
		Bridge:     installplan.BridgeConfig{SSHHost: "192.0.2.1", SSHIdentity: "/private/key with 'quote"},
		Automation: &installplan.AutomationConfig{KnownHostsFile: "/private/pins with 'quote"},
	}
	proxy := retainedProxyCommand(p)
	common := "-o " + shellQuote("ProxyCommand="+proxy)
	command := exec.Command(
		"python3",
		"-c",
		`import json,shlex,sys; a=shlex.split(sys.argv[1]); print(json.dumps(shlex.split(a[1].split('=',1)[1])))`,
		common,
	)
	raw, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	if err = json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	want := retainedSSH(p, p.Bridge.SSHHost, p.BridgeSSHIdentity(), false, false)
	want = append(want, "-W", "%h:%p", "root@192.0.2.1")
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatal("proxy tokenization changed pinned argv")
	}
	if got[len(got)-3] != "-W" {
		t.Fatal("forwarding option must precede destination")
	}
	direct := retainedSSH(p, "192.0.2.3", "/private/database-key", true, true)
	found := false
	for _, arg := range direct {
		if arg == "ProxyCommand="+proxy {
			found = true
		}
	}
	if !found {
		t.Fatal("Ansible and direct collector must share the proxy")
	}
}

func TestRecoveryToolNameFilterAllowsOnlyNamedJSON(t *testing.T) {
	for _, name := range []string{"ssh_policy.json", "recovery.py", "ultra-monitor.service", "ultra-monitor.timer"} {
		if !isRecoveryToolName(name) {
			t.Errorf("expected %q to be a recovery tool", name)
		}
	}
	for _, name := range []string{"other.json", "ssh_policy.yaml", "test_ssh_policy.json"} {
		if isRecoveryToolName(name) {
			t.Errorf("unexpected recovery tool %q", name)
		}
	}
	if isRecoverySystemdUnit("ssh_policy.json") || !isRecoverySystemdUnit("ultra-monitor.service") {
		t.Fatal("recovery data and systemd unit suffixes were not distinguished")
	}
}

func TestRecoveryPreparationFleetIdentityAllowsPublicKeyComment(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ultra-fleet")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{"id_ed25519": 0600, "id_ed25519.pub": 0644} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("fixture"), mode); err != nil {
			t.Fatal(err)
		}
	}
	keygen := filepath.Join(t.TempDir(), "ssh-keygen")
	program := strings.ReplaceAll(recoveryPreparationFleetIdentityProgram, "Path('/etc/ultra-fleet')", "Path("+strconv.Quote(root)+")")
	program = strings.ReplaceAll(program, "'/usr/bin/ssh-keygen'", strconv.Quote(keygen))
	program = strings.ReplaceAll(program, "for path in [root,*root.parents]:", "for path in [root]:")
	program = strings.ReplaceAll(program, "info.st_uid==0", "info.st_uid==os.geteuid()")
	program = strings.ReplaceAll(program, "allowed={0,pwd.getpwnam('ultra-relay').pw_uid}", "allowed={os.geteuid()}")
	if strings.Contains(program, "Path('/etc/ultra-fleet')") || strings.Contains(program, "info.st_uid==0") {
		t.Fatal("test fixture did not isolate host-specific checks")
	}
	for _, tc := range []struct {
		name, generated, published string
		wantSuccess                bool
	}{
		{"commented key", "ssh-ed25519 Zml4dHVyZQ== host-comment", "ssh-ed25519 Zml4dHVyZQ== published-comment", true},
		{"uncommented key", "ssh-ed25519 Zml4dHVyZQ==", "ssh-ed25519 Zml4dHVyZQ==", true},
		{"different key", "ssh-ed25519 ZGlmZmVyZW50", "ssh-ed25519 Zml4dHVyZQ==", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub := []byte(tc.published + "\n")
			if err := os.WriteFile(filepath.Join(root, "id_ed25519.pub"), pub, 0644); err != nil {
				t.Fatal(err)
			}
			stub := "#!/bin/sh\nprintf '%s\\n' " + strconv.Quote(tc.generated) + "\n"
			if err := os.WriteFile(keygen, []byte(stub), 0700); err != nil {
				t.Fatal(err)
			}
			err := exec.Command("python3", "-I", "-c", program).Run()
			if (err == nil) != tc.wantSuccess {
				t.Fatalf("fleet public key validation success=%v, want %v: %v", err == nil, tc.wantSuccess, err)
			}
		})
	}
}

func TestRetainedReconcileReceiptCreateOnlyReplay(t *testing.T) {
	d := t.TempDir()
	_ = os.Chmod(d, 0700)
	p := filepath.Join(d, "evidence.json")
	for i := 0; i < 2; i++ {
		if err := publishRetainedReconcile(p, []byte(`{"verified":true}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := publishRetainedReconcile(p, []byte(`{"different":true}`)); err == nil {
		t.Fatal("receipt overwritten")
	}
}

func TestUpgradeDomainAuthorizationBoundToEveryDesiredName(t *testing.T) {
	s, request := runtimeHostFixture(t)
	in := runtimeProbeInput{
		Request:            request,
		SubscriptionDomain: "sync.example.com",
		VPNDomain:          "edge.example.com",
		BotDomain:          "bot.example.com",
		DomainTransaction:  strings.Repeat("a", 64),
	}
	dir := s.path("var/lib/ultra-ingress/upgrade-" + in.DomainTransaction)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	binding := map[string]any{
		"version": 1, "transaction": in.DomainTransaction,
		"evidence": upgradeDomainEvidence{Verified: true},
		"desired": map[string]string{
			"subscription": in.SubscriptionDomain,
			"vpn":          in.VPNDomain,
			"backend":      in.BotDomain,
			"public_host":  in.Request.Bridge.PublicHost,
		},
		"policy": map[string]any{"dns_ttl": 300, "backend_port": 18080, "staging_port": 18443},
	}
	raw, _ := json.Marshal(binding)
	if err := os.WriteFile(filepath.Join(dir, "binding.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if !s.authorizedDomainTransition(in) {
		t.Fatal("exact binding rejected")
	}
	changed := in
	changed.BotDomain = "foreign.example.com"
	if s.authorizedDomainTransition(changed) {
		t.Fatal("backend substitution accepted")
	}
	changed = in
	changed.Request.Bridge.PublicHost = "foreign.example.com"
	if s.authorizedDomainTransition(changed) {
		t.Fatal("dial host substitution accepted")
	}
	changed = in
	changed.DomainTransaction = strings.Repeat("b", 64)
	if s.authorizedDomainTransition(changed) {
		t.Fatal("foreign transaction accepted")
	}
	if err := os.Chmod(filepath.Join(dir, "binding.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if s.authorizedDomainTransition(in) {
		t.Fatal("public binding accepted")
	}
}

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

func TestRuntimeTransportRequestBoundReplayAndExactRollback(t *testing.T) {
	s, request := runtimeHostFixture(t)
	// Establish a matching tunable runtime, then change a setting requiring no
	// external firewall/TLS/service provisioning. Credentials remain host-local.
	request.Bridge.PublicHost = "vpn.example.com"
	request.Features.LogLevel = "info"
	if _, err := s.prepare(request); err != nil {
		t.Fatal(err)
	}
	if _, err := s.transition(request.Transaction, false); err != nil {
		t.Fatal(err)
	}
	path, _ := s.journalPath(request.Transaction)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	before := []runtimeHostImage{}
	for _, file := range runtimeHostFiles {
		image, err := s.image(s.path(file))
		if err != nil {
			t.Fatal(err)
		}
		before = append(before, image)
	}
	request.Features.DomainDirect = "example.net"
	in := runtimeProbeInput{Request: request, BotActive: true, Action: "prepare"}
	probe, err := inspectRuntimeHost(s, in)
	if err != nil || !probe.RuntimeChanged || probe.DomainChanged || len(probe.Transitions) != 0 {
		t.Fatalf("probe: %+v %v", probe, err)
	}
	for i := 0; i < 2; i++ {
		result, err := runtimeHostTransport(s, in)
		if err != nil || result.Status != "prepared" || !result.BotActive {
			t.Fatalf("prepare replay: %+v %v", result, err)
		}
	}
	changed := in
	changed.Request.Features.DomainDirect = "other.example.net"
	if _, err = runtimeHostTransport(s, changed); err == nil {
		t.Fatal("different request resumed a host transaction")
	}
	in.Action, in.BotActive = "apply", false
	result, err := runtimeHostTransport(s, in)
	if err != nil || result.Status != "applied" || !result.BotActive {
		t.Fatalf("apply lost original service state: %+v %v", result, err)
	}
	if _, err = runtimeHostTransport(s, in); err != nil {
		t.Fatal("idempotent apply", err)
	}
	in.Action = "rollback"
	if _, err = runtimeHostTransport(s, in); err != nil {
		t.Fatal(err)
	}
	if _, err = runtimeHostTransport(s, in); err != nil {
		t.Fatal("idempotent rollback", err)
	}
	for i, file := range runtimeHostFiles {
		after, err := s.image(s.path(file))
		if err != nil || !runtimeHostImagesEqual(before[i], after) {
			t.Fatal("rollback changed exact prior image", err)
		}
	}
	in.Action = "apply"
	if _, err = runtimeHostTransport(s, in); err == nil {
		t.Fatal("finished transaction reapplied")
	}
}

func TestRuntimeRollbackWithoutPreparedJournalDoesNotAuthorizeServiceMutation(t *testing.T) {
	s, request := runtimeHostFixture(t)
	in := runtimeProbeInput{Request: request, Action: "status", BotActive: true}
	status, err := runtimeHostTransport(s, in)
	if err != nil || !status.Verified || status.Bound {
		t.Fatalf("unprepared transaction authorized service changes: %+v %v", status, err)
	}
	in.Action = "rollback"
	result, err := runtimeHostTransport(s, in)
	if err != nil || !result.Verified || result.Bound || result.Status != "rolled_back" {
		t.Fatalf("rollback touched unprepared transaction: %+v %v", result, err)
	}
	if err = os.Remove(s.path(runtimeHostStateDir)); err != nil {
		t.Fatal(err)
	}
	result, err = runtimeHostTransport(s, in)
	if err != nil || result.Bound {
		t.Fatal("absent journal directory authorized changes", err)
	}
}

func TestRuntimeTransitionNativeExactBindingApplyAndRollback(t *testing.T) {
	for _, change := range []struct {
		name   string
		update func(*runtimeHostRequest)
	}{
		{"tunnel", func(r *runtimeHostRequest) { r.Features.Transport = "splithttp"; r.Features.SplitHTTPPath = "/changed" }},
		{"listener", func(r *runtimeHostRequest) { r.Bridge.VLESSPort = 7444; r.Bridge.AdminListen = "127.0.0.1:8444" }},
		{"tls-policy", func(r *runtimeHostRequest) { r.Features.GenerateExitTLS = true }},
	} {
		t.Run(change.name, func(t *testing.T) {
			store, request := runtimeHostFixture(t)
			request.Bridge.PublicHost = "vpn.example.com"
			change.update(&request)
			input := runtimeProbeInput{Request: request, Action: "prepare"}
			before := []runtimeHostImage{}
			for _, name := range runtimeHostFiles {
				image, err := store.image(store.path(name))
				if err != nil {
					t.Fatal(err)
				}
				before = append(before, image)
			}
			probe, err := inspectRuntimeHost(store, input)
			if err != nil {
				t.Fatal(err)
			}
			if len(probe.Transitions) == 0 || probe.EffectsPlan == nil {
				t.Fatal("transition lost public effect plan")
			}
			if _, err = runtimeHostTransport(store, input); err == nil {
				t.Fatal("uncheckpointed transition accepted")
			}
			bound := input
			bound.Action = ""
			bound.BotActive = false
			binding := map[string]any{
				"version":        1,
				"state":          "prepared",
				"binding_sha256": runtimeHostDigest(bound),
				"plan":           probe.EffectsPlan,
			}
			raw, _ := json.Marshal(binding)
			path, _ := store.journalPath(request.Transaction)
			if err := os.WriteFile(strings.TrimSuffix(path, ".json")+".effects.json", raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = runtimeHostTransport(store, input); err != nil {
				t.Fatal("checkpointed native prepare", err)
			}
			input.Action = "apply"
			if _, err = runtimeHostTransport(store, input); err != nil {
				t.Fatal(err)
			}
			input.Action = "status"
			status, err := runtimeHostTransport(store, input)
			if err != nil || status.EffectsPlan == nil {
				t.Fatal("replay lost exact effect plan", err)
			}
			input.Action = "rollback"
			if _, err = runtimeHostTransport(store, input); err != nil {
				t.Fatal(err)
			}
			for index, name := range runtimeHostFiles {
				image, err := store.image(store.path(name))
				if err != nil || !runtimeHostImagesEqual(before[index], image) {
					t.Fatal("rollback did not restore exact native file", err)
				}
			}
		})
	}
}

func TestRuntimeTransitionPlanRestrictsExposureAndFixedTLSPaths(t *testing.T) {
	input := runtimeProbeInput{Request: runtimeHostRequest{Role: config.RoleBridge}}
	spec := config.Spec{Role: config.RoleBridge, VLESSPort: 7443, AdminListen: "0.0.0.0:8443"}
	raw, _ := json.Marshal(spec)
	if _, err := buildRuntimeTransitionPlan(input, raw, []installplan.RuntimeTransitionKind{installplan.RuntimeTransitionListener}); err == nil {
		t.Fatal("new public admin exposure accepted")
	}
	spec.AdminListen = "127.0.0.1:8444"
	spec.BotTelegramProxy = &config.BotTelegramProxySpec{Enabled: true, ListenAddress: "0.0.0.0", Port: 10809}
	raw, _ = json.Marshal(spec)
	if _, err := buildRuntimeTransitionPlan(input, raw, []installplan.RuntimeTransitionKind{installplan.RuntimeTransitionListener}); err == nil {
		t.Fatal("public bot exposure accepted")
	}
	input.Request.Role = config.RoleExit
	spec.Role = config.RoleExit
	spec.ExitCertPaths = config.CertPaths{CertFile: "/arbitrary/cert", KeyFile: "/arbitrary/key"}
	raw, _ = json.Marshal(spec)
	if _, err := buildRuntimeTransitionPlan(input, raw, []installplan.RuntimeTransitionKind{installplan.RuntimeTransitionTLS}); err == nil {
		t.Fatal("arbitrary TLS paths accepted")
	}
}

func TestRuntimeTransitionEffectAuthorizationRejectsPlanAndRequestDrift(t *testing.T) {
	store, request := runtimeHostFixture(t)
	request.Bridge.PublicHost = "vpn.example.com"
	request.Bridge.VLESSPort = 7444
	input := runtimeProbeInput{Request: request}
	probe, err := inspectRuntimeHost(store, input)
	if err != nil {
		t.Fatal(err)
	}
	binding := map[string]any{"version": 1, "state": "prepared", "binding_sha256": runtimeHostDigest(input), "plan": probe.EffectsPlan}
	raw, _ := json.Marshal(binding)
	path, _ := store.journalPath(request.Transaction)
	effectPath := strings.TrimSuffix(path, ".json") + ".effects.json"
	if err := os.WriteFile(effectPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if !store.authorizedRuntimeTransitions(input, probe.Transitions, probe.EffectsPlan) {
		t.Fatal("exact plan rejected")
	}
	altered := *probe.EffectsPlan
	altered.Ports = []int{9999}
	if store.authorizedRuntimeTransitions(input, probe.Transitions, &altered) {
		t.Fatal("different firewall target authorized")
	}
	input.Request.Features.LogLevel = "other"
	if store.authorizedRuntimeTransitions(input, probe.Transitions, probe.EffectsPlan) {
		t.Fatal("changed native request authorized")
	}
	if err := os.Chmod(effectPath, 0644); err != nil {
		t.Fatal(err)
	}
	input.Request.Features.LogLevel = request.Features.LogLevel
	if store.authorizedRuntimeTransitions(input, probe.Transitions, probe.EffectsPlan) {
		t.Fatal("public effect checkpoint authorized")
	}
}

func TestRuntimeTunnelPortRequiresAuthoritativeDBCheckpoint(t *testing.T) {
	for _, role := range []config.Role{config.RoleBridge, config.RoleExit} {
		prior := config.Spec{Role: role, VLESSPort: 9443, Exit: config.ExitTunnelSpec{Port: 9443}}
		desired := prior
		if role == config.RoleExit {
			desired.VLESSPort = 9444
		} else {
			desired.Exit.Port = 9444
		}
		before, _ := json.Marshal(prior)
		after, _ := json.Marshal(desired)
		_, err := buildRuntimeTransitionPlan(
			runtimeProbeInput{Request: runtimeHostRequest{Role: role}},
			after,
			[]installplan.RuntimeTransitionKind{installplan.RuntimeTransitionTunnel, installplan.RuntimeTransitionListener},
			before,
		)
		if err == nil || !strings.Contains(err.Error(), "tunnel_port_db_checkpoint_required") {
			t.Fatal("DB-backed port delta accepted without bridge CAS journal", err)
		}
	}
}

func TestValidateSubscriptionKeyringRejectsInvalidRings(t *testing.T) {
	valid := `{"active":"v1","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`
	for _, raw := range []string{
		`{"active":"v2","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"active":"v1","keys":{"bad id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"active":"v1","keys":{"v1":"AA=="}}`,
		`{"active":"v1","active":"v1","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"active":"v1","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"active":"v1","keys":{"v1":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},"extra":true}`,
	} {
		if err := validateSubscriptionKeyring([]byte(raw)); err == nil {
			t.Fatalf("accepted invalid ring: %s", raw)
		}
	}
	if err := validateSubscriptionKeyring([]byte(valid)); err != nil {
		t.Fatalf("rejected valid ring: %v", err)
	}
}
