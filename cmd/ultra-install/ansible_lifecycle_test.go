package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestForwardedLoopbackSSHNeverSelectsBridgeLocalRuntime(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "198.18.0.10", ""} {
		p := &installplan.InstallPlan{Bridge: installplan.BridgeConfig{SSHHost: "127.0.0.1", Address: address}}
		if localLifecycleBridge(p) {
			t.Fatal("a loopback SSH forwarding endpoint selected the operator process", address)
		}
	}
}
func TestLifecycleIdentityIsStableAndAttemptSpecific(t *testing.T) {
	original := lifecycleID("/private/attempt-a")
	resumedPath := strings.Join([]string{"", "private", "attempt-a"}, "/")
	if lifecycleID(resumedPath) != original {
		t.Fatal("resume rotated root reservation")
	}
	if lifecycleID("/private/attempt-a") == lifecycleID("/private/attempt-b") {
		t.Fatal("fresh attempt reused root reservation")
	}
}

type identityFixtureInfo struct {
	os.FileInfo
	mode  os.FileMode
	owner uint32
}

func (f identityFixtureInfo) Mode() os.FileMode { return f.mode }
func (f identityFixtureInfo) Sys() any          { return &syscall.Stat_t{Uid: f.owner} }

func TestNonLoopbackAliasNeedsMachineBoundPrivateIdentity(t *testing.T) {
	p := &installplan.InstallPlan{Bridge: installplan.BridgeConfig{SSHHost: "198.18.0.10", Address: "198.18.0.10"}}
	machine := []byte("0123456789abcdef0123456789abcdef\n")
	identity := fmt.Sprintf(`{"schema_version":1,"role":"bridge","address":"198.18.0.10","machine_sha256":"%x"}`, sha256.Sum256([]byte(strings.TrimSpace(string(machine)))))
	info := identityFixtureInfo{mode: 0600, owner: 0}
	if validLocalLifecycleIdentity(p, info, nil, machine) {
		t.Fatal("matching operator alias was enough without target identity")
	}
	if validLocalLifecycleIdentity(p, info, []byte(identity), []byte("abcdef0123456789abcdef0123456789ab")) {
		t.Fatal("cloned deployment receipt selected a different operator machine")
	}
	if !validLocalLifecycleIdentity(p, info, []byte(identity), machine) {
		t.Fatal("actual private target identity rejected")
	}
	if validLocalLifecycleIdentity(p, identityFixtureInfo{mode: 0644, owner: 0}, []byte(identity), machine) {
		t.Fatal("public identity accepted")
	}
	if validLocalLifecycleIdentity(p, identityFixtureInfo{mode: 0600, owner: 1000}, []byte(identity), machine) {
		t.Fatal("non-root identity accepted")
	}
}
func TestLocalExecutionCannotBeInjectedAndCopiesKeepOnlySameTargetDecision(t *testing.T) {
	p := &installplan.InstallPlan{Bridge: installplan.BridgeConfig{SSHHost: "198.18.0.10", Address: "198.18.0.10"}}
	if err := json.Unmarshal([]byte(`{"ControllerLocal":true,"ControllerLocalTarget":"198.18.0.10|198.18.0.10"}`), p); err != nil {
		t.Fatal(err)
	}
	if p.ControllerLocal != nil {
		t.Fatal("configuration injected local execution bypass")
	}
	local := false
	p.ControllerLocal = &local
	p.ControllerLocalTarget = p.Bridge.SSHHost + "|" + p.Bridge.Address
	clone := *p
	if localLifecycleBridge(&clone) {
		t.Fatal("same-target copy changed frozen gateway mode")
	}
	clone.Bridge.SSHHost = "127.0.0.1"
	clone.Bridge.Address = "127.0.0.1"
	local = true
	p.ControllerLocal = &local
	if localLifecycleBridge(&clone) {
		t.Fatal("different target inherited source local mode")
	}
}

func TestAttestedLocalBridgeWithUnavailableBrokerNeverFallsBackToSSH(t *testing.T) {
	root := t.TempDir()
	t.Setenv("ULTRA_ANSIBLE_SOCKET", filepath.Join(root, "missing-controller.sock"))
	p := &installplan.InstallPlan{Bridge: installplan.BridgeConfig{SSHHost: "198.18.0.10", Address: "198.18.0.10"}}
	machine := []byte("0123456789abcdef0123456789abcdef\n")
	identity := fmt.Sprintf(`{"schema_version":1,"role":"bridge","address":"198.18.0.10","machine_sha256":"%x"}`, sha256.Sum256([]byte(strings.TrimSpace(string(machine)))))
	// Model the same root-owned physical attestation used by the production
	// selector without requiring root or writing the machine's system receipt.
	local := validLocalLifecycleIdentity(p, identityFixtureInfo{mode: 0600, owner: 0}, []byte(identity), machine)
	if !local {
		t.Fatal("physical identity rejected")
	}
	p.ControllerLocal = &local
	p.ControllerLocalTarget = p.Bridge.SSHHost + "|" + p.Bridge.Address
	err := ansibleLifecycle(context.Background(), p, nil, root, "/usr/bin/python3", "/bin/false", "applying", true)
	if err == nil || !strings.Contains(err.Error(), "controller unavailable") {
		t.Fatal("missing broker did not fail authenticated local transition", err)
	}
	if !localLifecycleBridge(p) {
		t.Fatal("broker outage switched physical target to SSH")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatal("broker outage launched/staged a remote Ansible fallback", err)
	}
}
