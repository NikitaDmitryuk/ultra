package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestNativeAdoptionFreezesInitialExecutorAcrossBrokerInstallation(t *testing.T) {
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(stateRoot, "attempt")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	p := &installplan.InstallPlan{
		BridgeNative: true,
		AdoptRuntime: true,
		Bridge:       installplan.BridgeConfig{SSHHost: "192.0.2.1", Address: "192.0.2.1"},
	}
	sha := strings.Repeat("a", 64)
	attest := func(*installplan.InstallPlan) (string, error) { return sha, nil }
	lock, err := freezeBootstrapExecutionWith(p, directory, stateRoot, attest)
	if err != nil || lock != stateRoot {
		t.Fatal(lock, err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "execution-mode.json"))
	if err != nil {
		t.Fatal(err)
	}
	var mode frozenExecution
	if json.Unmarshal(raw, &mode) != nil || !mode.Native || mode.Local || mode.NativeMachineSHA != sha {
		t.Fatal("native identity not frozen")
	}
	local := true
	p.ControllerLocal = &local
	p.ControllerLocalTarget = mode.Target
	if localLifecycleBridge(p) {
		t.Fatal("broker appearance changed explicit initial execution")
	}
	if lock, err = freezeBootstrapExecutionWith(p, directory, stateRoot, attest); err != nil || lock != stateRoot {
		t.Fatal("retry moved its lock", err)
	}
	sha = strings.Repeat("b", 64)
	if _, err = freezeBootstrapExecutionWith(p, directory, stateRoot, attest); err == nil {
		t.Fatal("different physical machine accepted")
	}
	sha = strings.Repeat("a", 64)
	p.BridgeNative = false
	if _, err = freezeBootstrapExecutionWith(p, directory, stateRoot, attest); err == nil {
		t.Fatal("native mode dropped from frozen attempt")
	}
}

func TestNativeStageRetryChecksMachineBeforeAnyLeaseOrAction(t *testing.T) {
	for _, fault := range []string{"none", "machine", "broker-unavailable", "lifecycle_retired", "lifecycle_not_owned", "lifecycle_released", "lifecycle_mismatch", "malformed-attachment", "action-failed"} {
		t.Run(fault, func(t *testing.T) {
			const state = "/tmp/native-operator"
			attempt := state + "/bootstrap-fixture/attempt"
			directory := attempt + "/bootstrap-exit"
			request, _ := json.Marshal(
				map[string]any{"inventory": map[string]any{}, "variables": map[string]any{"ultra_lock_directory": state}},
			)
			hash := sha256.Sum256(request)
			identity := hex.EncodeToString(hash[:])
			job, _ := json.Marshal(
				map[string]any{"schema_version": 1, "operation": "bootstrap-exit", "request_sha256": identity, "binary_sha256": identity},
			)
			mode, _ := json.Marshal(
				frozenExecution{
					Schema:            1,
					Target:            "192.0.2.1|192.0.2.1",
					Native:            true,
					NativeMachineSHA:  strings.Repeat("a", 64),
					LockDirectory:     state,
					OperatorDirectory: state + "/operator",
				},
			)
			files := map[string][]byte{
				directory + "/request.json":      request,
				directory + "/job.json":          job,
				attempt + "/execution-mode.json": mode,
			}
			locked, acted, attached, brokerReleased, operatorReleased, stateReleased := false, false, false, false, false, false
			deps := frozenBootstrapRetryDependencies{
				readPrivate: func(path string) ([]byte, error) {
					raw, ok := files[path]
					if !ok {
						return nil, os.ErrNotExist
					}
					return raw, nil
				},
				nativeMachine: func(sha string) bool {
					if sha != strings.Repeat("a", 64) {
						t.Fatal("machine binding lost")
					}
					return fault != "machine"
				},
				operator: func(ctx context.Context, path string) (context.Context, func(), error) {
					locked = true
					return ctx, func() { operatorReleased = true }, nil
				},
				remoteLock: func(ctx context.Context, path string) (context.Context, func(), error) {
					locked = true
					return context.WithValue(ctx, retryAttachmentTestKey{}, state), func() { stateReleased = true }, nil
				},
				attach: func(ctx context.Context, lock, id string) (context.Context, func(), error) {
					attached = true
					if lock != bootstrapBrokerLockDirectory || id != lifecycleID(attempt) || ctx.Value(retryAttachmentTestKey{}) != state {
						t.Fatal("native retry lost canonical lifecycle or stateRoot context")
					}
					if fault != "none" && fault != "action-failed" {
						return ctx, nil, errors.New(fault)
					}
					return context.WithValue(
						ctx,
						retryAttachmentTestKey{},
						"broker-context-must-not-replace-state",
					), func() { brokerReleased = true }, nil
				},
			}
			_, err := withFrozenBootstrapStageLeaseWith(
				context.Background(),
				directory,
				deps,
				func(ctx context.Context) (deployansible.Receipt, error) {
					acted = true
					if !attached || brokerReleased || operatorReleased || stateReleased || ctx.Value(retryAttachmentTestKey{}) != state {
						t.Fatal("native callback lost original execution context or held leases")
					}
					if fault == "action-failed" {
						return deployansible.Receipt{}, errors.New("action failed")
					}
					return deployansible.Receipt{State: "succeeded"}, nil
				},
			)
			if fault == "action-failed" && (err == nil || !acted || !brokerReleased || !operatorReleased || !stateReleased) {
				t.Fatalf("failed action leaked native leases: %v", err)
			}
			if fault == "none" && (err != nil || !locked || !acted || !brokerReleased || !operatorReleased || !stateReleased) {
				t.Fatal("valid native retry failed", err)
			}
			if fault == "machine" && (err == nil || locked || attached || acted) {
				t.Fatal("different machine acquired lease or replayed")
			}
			if fault != "none" && fault != "machine" && fault != "action-failed" &&
				(err == nil || !attached || acted || !operatorReleased || !stateReleased) {
				t.Fatalf("invalid lifecycle reached action or leaked locks: %v", err)
			}
		})
	}
}

func TestNativeInventoryKeepsExitConnectionsOverSSH(t *testing.T) {
	root := t.TempDir()
	pins := filepath.Join(root, "known_hosts")
	if err := os.WriteFile(pins, []byte("fixture host pins"), 0600); err != nil {
		t.Fatal(err)
	}
	p := &installplan.InstallPlan{
		BridgeNative: true,
		AdoptRuntime: true,
		Bridge:       installplan.BridgeConfig{RemoteDir: "/etc/ultra-relay", SSHHost: "192.0.2.1"},
		SSH:          installplan.SSHConfig{User: "root", Identity: filepath.Join(root, "identity")},
		Automation:   &installplan.AutomationConfig{KnownHostsFile: pins},
		Exits:        []installplan.ExitNode{{Name: "exit", SSHHost: "192.0.2.2"}},
	}
	inventory, err := bootstrapInventoryWithNativeAttestation(
		p,
		root,
		func(*installplan.InstallPlan) (string, error) { return strings.Repeat("a", 64), nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	children := inventory["all"].(map[string]any)["children"].(map[string]any)
	bridge := children["bridge"].(map[string]any)["hosts"].(map[string]any)["bridge"].(map[string]any)
	exit := children["exits"].(map[string]any)["hosts"].(map[string]any)["exit_0"].(map[string]any)
	if bridge["ansible_connection"] != "local" || exit["ansible_connection"] != nil || exit["ansible_host"] != "192.0.2.2" {
		t.Fatal("native executor lost local bridge or SSH exit")
	}
}
