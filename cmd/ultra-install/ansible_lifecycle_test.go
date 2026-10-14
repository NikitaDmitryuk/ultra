package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestReservedBootstrapEarlyFailureRestoresSchedulesAndReleasesOnlyExistingGate(t *testing.T) {
	for _, tc := range []struct {
		name         string
		supportsGate bool
		failDrain    bool
		noSchedules  bool
		failRestore  bool
		maintenance  bool
		operations   string
	}{
		{name: "legacy-before-maintenance", operations: "resume-schedules:\n"},
		{name: "capable-before-maintenance", supportsGate: true, operations: "lifecycle:applying\nresume-schedules:\nlifecycle:released\n"},
		{name: "capable-drain-failure", supportsGate: true, failDrain: true, operations: "lifecycle:applying\nresume-schedules:\nlifecycle:released\n"},
		{name: "fresh-capable-drain-failure", supportsGate: true, failDrain: true, noSchedules: true, operations: "lifecycle:applying\nlifecycle:released\n"},
		{name: "capable-schedule-restore-failure", supportsGate: true, failRestore: true, operations: "lifecycle:applying\nresume-schedules:\n"},
		{name: "legacy-after-maintenance", maintenance: true, operations: "resume-adoption:\nresume-schedules:\nlifecycle:released\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			python, err := exec.LookPath("python3")
			if err != nil {
				t.Skip("python unavailable")
			}
			root := t.TempDir()
			if err = os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(root, "attempt")
			if err = os.Mkdir(directory, 0700); err != nil {
				t.Fatal(err)
			}
			// A failed capture can leave its schedule receipt without reaching
			// maintenance; a retry must restore those schedules before returning.
			if !tc.noSchedules {
				if err = os.WriteFile(filepath.Join(directory, "adoption-schedules.json"), []byte(`["ultra-recovery-backup.timer"]`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.maintenance {
				if err = os.WriteFile(filepath.Join(directory, "adoption-maintenance.json"), []byte(`{"legacy":true}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			stub := filepath.Join(root, "ansible-playbook")
			source := "#!" + python + `
import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
variables=json.loads((job/'variables.json').read_text())
operation=json.loads((job/'job.json').read_text())['operation']
phase=variables.get('ultra_lifecycle_phase','')
with (job.parent.parent/'operations').open('a') as stream:stream.write(operation+':'+phase+'\n')
if operation=='resume-schedules':
 assert variables['ultra_adoption_schedules']==['ultra-recovery-backup.timer']
 FAIL_RESTORE
if operation=='lifecycle' and phase=='applying':
 assert variables['ultra_lifecycle_drain'] is True
 FAIL_DRAIN
result=pathlib.Path(variables['ultra_result_file']);result.write_text(json.dumps({'verified':True}));result.chmod(0o600)
`
			failure := "pass"
			if tc.failDrain {
				failure = "sys.exit(1)"
			}
			source = strings.Replace(source, "FAIL_DRAIN", failure, 1)
			restoreFailure := "pass"
			if tc.failRestore {
				restoreFailure = "sys.exit(1)"
			}
			source = strings.Replace(source, "FAIL_RESTORE", restoreFailure, 1)
			if err = os.WriteFile(stub, []byte(source), 0700); err != nil {
				t.Fatal(err)
			}
			ctx, release, err := deployansible.WithOperationLock(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			p := &installplan.InstallPlan{Bridge: installplan.BridgeConfig{SSHHost: "192.0.2.1"}}
			inspection := map[string]bootstrapInspection{"bridge": {Architecture: "amd64"}}
			if tc.supportsGate {
				inspection["bridge"] = bootstrapInspection{Architecture: "amd64", Capabilities: []string{"lifecycle-gate-v1"}}
			}
			// No automation release forces a pre-base failure, without executing
			// any controller preparation or touching a real relay.
			_, _, err = prepareReservedBootstrap(ctx, p, map[string]any{"all": map[string]any{}}, inspection, directory, root, python, stub)
			if err == nil {
				t.Fatal("pre-base failure reported success")
			}
			if !tc.failDrain && !tc.failRestore && err.Error() != "independent controller release required for fleet lifecycle" {
				t.Fatal("cleanup changed original preparation failure", err)
			}
			operations, readErr := os.ReadFile(filepath.Join(root, "operations"))
			if readErr != nil || string(operations) != tc.operations {
				t.Fatalf("wrong cleanup order: %q, read error: %v", operations, readErr)
			}
		})
	}
}

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
