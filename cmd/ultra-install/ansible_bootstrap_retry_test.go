package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type retryAttachmentTestKey struct{}

func TestFrozenLocalBootstrapRetryAttachesSameBrokerLease(t *testing.T) {
	for _, fault := range []string{"none", "machine", "inventory", "execution-lock", "root-private", "operator-missing", "operator-path", "operator-layout", "operator-busy", "broker", "lifecycle_retired", "lifecycle_not_owned"} {
		t.Run(fault, func(t *testing.T) {
			attempt := "/tmp/original-state/bootstrap-plan/attempt-frozen"
			directory := filepath.Join(attempt, "apply")
			inventory := syntheticLocalBootstrapRetryInventory(t)
			request, _ := json.Marshal(
				map[string]any{"inventory": inventory, "variables": map[string]any{"ultra_lock_directory": bootstrapBrokerLockDirectory}},
			)
			digest := sha256.Sum256(request)
			job, _ := json.Marshal(
				map[string]any{
					"schema_version": 1,
					"operation":      "bootstrap",
					"request_sha256": hex.EncodeToString(digest[:]),
					"binary_sha256":  hex.EncodeToString(digest[:]),
				},
			)
			mode := frozenExecution{
				Schema:            1,
				Target:            "192.0.2.1|192.0.2.1",
				Local:             true,
				LockDirectory:     bootstrapBrokerLockDirectory,
				OperatorDirectory: "/tmp/original-state/operator",
			}
			if fault == "operator-missing" {
				mode.OperatorDirectory = ""
			}
			if fault == "operator-layout" {
				mode.OperatorDirectory = "/tmp/other-state/operator"
			}
			if fault == "operator-path" {
				mode.OperatorDirectory = "relative/operator"
			}
			if fault == "execution-lock" {
				mode.LockDirectory = "/tmp/wrong-lock"
			}
			modeRaw, _ := json.Marshal(mode)
			frozen, _ := json.Marshal(inventory)
			if fault == "inventory" {
				frozen = []byte(`{"all":{}}`)
			}
			files := map[string][]byte{
				filepath.Join(directory, "request.json"):        request,
				filepath.Join(directory, "job.json"):            job,
				filepath.Join(attempt, "execution-mode.json"):   modeRaw,
				filepath.Join(attempt, "inventory.frozen.json"): frozen,
			}
			read := func(path string) ([]byte, error) {
				raw, ok := files[path]
				if !ok {
					return nil, os.ErrNotExist
				}
				return raw, nil
			}
			attached, replayed, released, remote := false, false, false, false
			deps := frozenBootstrapRetryDependencies{readPrivate: read, readRootPrivate: func(path string) ([]byte, error) {
				if fault == "root-private" {
					return nil, errors.New("not root private")
				}
				return read(path)
			},
				machine: func(p *installplan.InstallPlan) bool {
					if p.ControllerLocal == nil || !*p.ControllerLocal || p.ControllerLocalTarget != mode.Target ||
						p.Bridge.SSHHost != "192.0.2.1" {
						t.Fatal("target changed")
					}
					return fault != "machine"
				},
				operator: func(ctx context.Context, path string) (context.Context, func(), error) {
					if path != mode.OperatorDirectory {
						t.Fatal("operator lock changed")
					}
					if fault == "operator-busy" {
						return ctx, nil, errors.New("operator already running")
					}
					return ctx, func() {}, nil
				},
				attach: func(ctx context.Context, lock, id string) (context.Context, func(), error) {
					attached = true
					if lock != bootstrapBrokerLockDirectory || id != lifecycleID(attempt) {
						t.Fatal("wrong lock or UUID")
					}
					if fault == "lifecycle_retired" || fault == "lifecycle_not_owned" {
						return ctx, nil, errors.New(fault)
					}
					if fault == "broker" {
						return ctx, nil, errors.New("broker retained lock unavailable")
					}
					return context.WithValue(ctx, retryAttachmentTestKey{}, id), func() { released = true }, nil
				},
				replay: func(ctx context.Context, path, python, exe string) (deployansible.Receipt, error) {
					replayed = true
					if ctx.Value(retryAttachmentTestKey{}) != lifecycleID(attempt) || path != directory {
						t.Fatal("attached lease not reused")
					}
					return deployansible.Receipt{State: "succeeded"}, nil
				},
				remoteLock: func(ctx context.Context, lock string) (context.Context, func(), error) {
					remote = true
					return ctx, func() {}, nil
				},
			}
			_, err := retryFrozenBootstrapOperatorWith(
				context.Background(),
				directory,
				"/usr/bin/python3",
				"/usr/bin/ansible-playbook",
				deps,
			)
			if fault == "none" {
				if err != nil || !attached || !replayed || !released {
					t.Fatal("local broker replay failed", err)
				}
			} else if err == nil || replayed {
				t.Fatal("invalid local retry accepted", fault)
			}
			if (fault == "lifecycle_retired" || fault == "lifecycle_not_owned") &&
				(err == nil || err.Error() != fault || !attached || released) {
				t.Fatal("broker rejection was not preserved before replay", err)
			}
			if remote {
				t.Fatal("local retry fell back to independent lock")
			}
			if fault != "none" && fault != "broker" && fault != "lifecycle_retired" && fault != "lifecycle_not_owned" && attached {
				t.Fatal("invalid local identity attached broker")
			}
		})
	}
}

func TestFrozenRemoteBootstrapRetryRejectsBeforeLocksOrAction(t *testing.T) {
	for _, kind := range []string{"remote", "legacy-no-mode"} {
		t.Run(kind, func(t *testing.T) {
			const lock = "/tmp/original-private-lock"
			request, _ := json.Marshal(
				map[string]any{"inventory": map[string]any{}, "variables": map[string]any{"ultra_lock_directory": lock}},
			)
			digest := sha256.Sum256(request)
			job, _ := json.Marshal(
				map[string]any{
					"schema_version": 1,
					"operation":      "bootstrap",
					"request_sha256": hex.EncodeToString(digest[:]),
					"binary_sha256":  hex.EncodeToString(digest[:]),
				},
			)
			mode, _ := json.Marshal(frozenExecution{Schema: 1, LockDirectory: lock, OperatorDirectory: lock + "/operator"})
			unexpectedLock := func(ctx context.Context, _ string) (context.Context, func(), error) {
				t.Fatal("unsupported remote retry acquired a lock")
				return ctx, func() {}, nil
			}
			deps := frozenBootstrapRetryDependencies{
				readPrivate: func(path string) ([]byte, error) {
					switch filepath.Base(path) {
					case "request.json":
						return request, nil
					case "job.json":
						return job, nil
					case "execution-mode.json":
						if kind == "remote" {
							return mode, nil
						}
					}
					return nil, os.ErrNotExist
				},
				operator: unexpectedLock, remoteLock: unexpectedLock,
				attach: func(ctx context.Context, _, _ string) (context.Context, func(), error) {
					t.Fatal("unsupported remote retry attached a broker lease")
					return ctx, func() {}, nil
				},
				replay: func(context.Context, string, string, string) (deployansible.Receipt, error) {
					t.Fatal("unsupported remote retry reached action")
					return deployansible.Receipt{}, nil
				},
			}
			_, err := retryFrozenBootstrapOperatorWith(context.Background(), "/tmp/legacy-fixture/apply", "python", "ansible", deps)
			if err == nil || err.Error() != "retry_remote_lifecycle_attachment_unsupported" {
				t.Fatalf("unexpected rejection: %v", err)
			}
		})
	}
}

func TestRootPrivateBootstrapRetrySourcesRejectPublicOrLinkedFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "execution-mode.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		if _, err := readRootPrivateBootstrapRetry(path); err == nil {
			t.Fatal("non-root local retry source accepted")
		}
		return
	}
	if _, err := readRootPrivateBootstrapRetry(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRootPrivateBootstrapRetry(path); err == nil {
		t.Fatal("public local retry source accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(root, "linked.json")
	if err := os.Symlink(path, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := readRootPrivateBootstrapRetry(linked); err == nil {
		t.Fatal("symlinked local retry source accepted")
	}
}

func TestFrozenLocalBootstrapRetrySerializesTwoInvocations(t *testing.T) {
	stateRoot := t.TempDir()
	operatorPath := filepath.Join(stateRoot, "operator")
	if err := os.Mkdir(operatorPath, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(stateRoot, "bootstrap-plan", "attempt-frozen", "apply")
	inventory := syntheticLocalBootstrapRetryInventory(t)
	request, _ := json.Marshal(
		map[string]any{"inventory": inventory, "variables": map[string]any{"ultra_lock_directory": bootstrapBrokerLockDirectory}},
	)
	digest := sha256.Sum256(request)
	job, _ := json.Marshal(
		map[string]any{
			"schema_version": 1,
			"operation":      "bootstrap",
			"request_sha256": hex.EncodeToString(digest[:]),
			"binary_sha256":  hex.EncodeToString(digest[:]),
		},
	)
	mode, _ := json.Marshal(
		frozenExecution{
			Schema:            1,
			Target:            "192.0.2.1|192.0.2.1",
			Local:             true,
			LockDirectory:     bootstrapBrokerLockDirectory,
			OperatorDirectory: operatorPath,
		},
	)
	frozen, _ := json.Marshal(inventory)
	read := func(path string) ([]byte, error) {
		switch filepath.Base(path) {
		case "request.json":
			return request, nil
		case "job.json":
			return job, nil
		case "execution-mode.json":
			return mode, nil
		case "inventory.frozen.json":
			return frozen, nil
		default:
			return nil, os.ErrNotExist
		}
	}
	attached := 0
	deps := frozenBootstrapRetryDependencies{
		readPrivate:     read,
		readRootPrivate: read,
		machine:         func(*installplan.InstallPlan) bool { return true },
		operator:        deployansible.WithOperationLock,
		attach: func(ctx context.Context, lock, id string) (context.Context, func(), error) {
			attached++
			return ctx, func() {}, nil
		},
	}
	deps.replay = func(ctx context.Context, path, python, executable string) (deployansible.Receipt, error) {
		second := deps
		second.replay = func(context.Context, string, string, string) (deployansible.Receipt, error) {
			t.Fatal("second invocation replayed before operator release")
			return deployansible.Receipt{}, nil
		}
		if _, err := retryFrozenBootstrapOperatorWith(context.Background(), directory, python, executable, second); err == nil {
			t.Fatal("second invocation shared operator lease")
		}
		return deployansible.Receipt{State: "succeeded"}, nil
	}
	if _, err := retryFrozenBootstrapOperatorWith(context.Background(), directory, "/usr/bin/python3", "/usr/bin/ansible-playbook", deps); err != nil {
		t.Fatal(err)
	}
	if attached != 1 {
		t.Fatal("second invocation attached broker")
	}
	_, release, err := deployansible.WithOperationLock(context.Background(), operatorPath)
	if err != nil {
		t.Fatal("operator lock was not released", err)
	}
	release()
}

// Build routing fixtures through the production inventory builder, so group
// names and native bridge flags cannot drift independently from their source.
func syntheticLocalBootstrapRetryInventory(t *testing.T) map[string]any {
	t.Helper()
	root := t.TempDir()
	pins := filepath.Join(root, "synthetic-known-hosts")
	if err := os.WriteFile(pins, []byte("synthetic pins only"), 0600); err != nil {
		t.Fatal(err)
	}
	local := true
	p := &installplan.InstallPlan{
		Bridge:          installplan.BridgeConfig{SSHHost: "192.0.2.1", Address: "192.0.2.1", RemoteDir: "/etc/ultra-relay"},
		SSH:             installplan.SSHConfig{User: "root", Identity: filepath.Join(root, "synthetic-identity")},
		Automation:      &installplan.AutomationConfig{KnownHostsFile: pins},
		ControllerLocal: &local, ControllerLocalTarget: "192.0.2.1|192.0.2.1",
	}
	inventory, err := bootstrapInventory(p, filepath.Join(root, "attempt-source"))
	if err != nil {
		t.Fatal(err)
	}
	return inventory
}

func TestFrozenStageLeaseRevalidatesOriginalInputsBeforeInternalCallback(t *testing.T) {
	for _, fault := range []string{"none", "request-changed", "job-changed", "receipt-changed"} {
		t.Run(fault, func(t *testing.T) {
			directory := "/tmp/frozen-native/apply"
			request, _ := json.Marshal(
				map[string]any{
					"inventory": map[string]any{},
					"variables": map[string]any{"ultra_lock_directory": "/tmp/original-private-lock"},
				},
			)
			digest := sha256.Sum256(request)
			job, _ := json.Marshal(
				map[string]any{
					"schema_version": 1,
					"operation":      "bootstrap",
					"request_sha256": hex.EncodeToString(digest[:]),
					"binary_sha256":  hex.EncodeToString(digest[:]),
				},
			)
			mode, _ := json.Marshal(
				frozenExecution{
					Schema:            1,
					Native:            true,
					LockDirectory:     "/tmp/original-private-lock",
					OperatorDirectory: "/tmp/original-private-lock/operator",
				},
			)
			var receipt []byte
			locked, called, released := false, false, false
			deps := frozenBootstrapRetryDependencies{
				readPrivate: func(path string) ([]byte, error) {
					switch filepath.Base(path) {
					case "execution-mode.json":
						return mode, nil
					case "request.json":
						return request, nil
					case "job.json":
						return job, nil
					case "receipt.json":
						if receipt != nil {
							return receipt, nil
						}
						return nil, os.ErrNotExist
					default:
						return nil, os.ErrNotExist
					}
				},
				nativeMachine: func(string) bool { return true },
				attach:        func(ctx context.Context, _, _ string) (context.Context, func(), error) { return ctx, func() {}, nil },
				operator: func(ctx context.Context, path string) (context.Context, func(), error) {
					if path != "/tmp/original-private-lock/operator" {
						t.Fatal("callback changed original operator")
					}
					return ctx, func() {}, nil
				},
				remoteLock: func(ctx context.Context, path string) (context.Context, func(), error) {
					if path != "/tmp/original-private-lock" {
						t.Fatal("callback acquired wrong original lock")
					}
					locked = true
					if fault == "request-changed" {
						request = []byte(`{}`)
					}
					if fault == "receipt-changed" {
						receipt = []byte(`{"schema_version":1,"operation":"bootstrap","state":"failed","request_sha256":"wrong"}`)
					}
					if fault == "job-changed" {
						job = []byte(`{}`)
					}
					return context.WithValue(ctx, retryAttachmentTestKey{}, path), func() { released = true }, nil
				},
			}
			_, err := withFrozenBootstrapStageLeaseWith(
				context.Background(),
				directory,
				deps,
				func(ctx context.Context) (deployansible.Receipt, error) {
					called = true
					if !locked || ctx.Value(retryAttachmentTestKey{}) != "/tmp/original-private-lock" {
						t.Fatal("internal callback did not receive original leased context")
					}
					return deployansible.Receipt{State: "succeeded"}, nil
				},
			)
			if fault == "none" {
				if err != nil || !called {
					t.Fatal("safe internal callback refused", err)
				}
			} else if err == nil || called {
				t.Fatal("changed frozen input reached internal callback")
			}
			if !released {
				t.Fatal("callback path leaked original lease")
			}
		})
	}
}

func TestRemoteCompatibilityRejectsEvenWhenOriginalLocksBecomeFree(t *testing.T) {
	for _, modeKind := range []string{"recorded-operator", "legacy-no-mode"} {
		t.Run(modeKind, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			operatorCtx, operatorRelease, err := withBootstrapOperatorLock(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			defer operatorRelease()
			_ = operatorCtx // The canonical transaction keeps this lock through checking.
			// Its fleet lock is deliberately free during asynchronous checking.
			_, fleetRelease, err := deployansible.WithOperationLock(context.Background(), root)
			if err != nil {
				t.Fatal("fixture fleet was not free", err)
			}
			fleetRelease()
			directory := filepath.Join(root, "bootstrap-plan", "attempt-original", "apply")
			if err = os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			request, _ := json.Marshal(
				map[string]any{"inventory": map[string]any{}, "variables": map[string]any{"ultra_lock_directory": root}},
			)
			digest := sha256.Sum256(request)
			job, _ := json.Marshal(
				map[string]any{
					"schema_version": 1,
					"operation":      "bootstrap",
					"request_sha256": hex.EncodeToString(digest[:]),
					"binary_sha256":  hex.EncodeToString(digest[:]),
				},
			)
			for name, raw := range map[string][]byte{"request.json": request, "job.json": job} {
				if err = os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if modeKind == "recorded-operator" {
				mode, _ := json.Marshal(
					frozenExecution{
						Schema:            1,
						Target:            "192.0.2.1|192.0.2.1",
						Local:             false,
						LockDirectory:     root,
						OperatorDirectory: filepath.Join(root, "operator"),
					},
				)
				if err = os.WriteFile(filepath.Join(filepath.Dir(directory), "execution-mode.json"), mode, 0600); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			action := func(ctx context.Context) (deployansible.Receipt, error) {
				called = true
				return deployansible.Receipt{State: "succeeded"}, nil
			}
			if _, err = withFrozenBootstrapStageLease(context.Background(), directory, action); err == nil || called {
				t.Fatal("remote callback overlapped canonical checking")
			}
			operatorRelease()
			if _, err = withFrozenBootstrapStageLease(context.Background(), directory, action); err == nil || called ||
				err.Error() != "retry_remote_lifecycle_attachment_unsupported" {
				t.Fatal("remote retry resumed without bridge lease", err)
			}
			_, release, err := withBootstrapOperatorLock(context.Background(), root)
			if err != nil {
				t.Fatal("compatibility callback leaked original operator", err)
			}
			release()
		})
	}
}

func TestRemoteCompatibilityRejectsUnprovedOriginalOperatorDirectory(t *testing.T) {
	for _, kind := range []string{"missing", "public", "recorded-wrong-parent"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(root, "plan", "attempt", "apply")
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			request, _ := json.Marshal(
				map[string]any{"inventory": map[string]any{}, "variables": map[string]any{"ultra_lock_directory": root}},
			)
			digest := sha256.Sum256(request)
			job, _ := json.Marshal(
				map[string]any{
					"schema_version": 1,
					"operation":      "bootstrap",
					"request_sha256": hex.EncodeToString(digest[:]),
					"binary_sha256":  hex.EncodeToString(digest[:]),
				},
			)
			for name, raw := range map[string][]byte{"request.json": request, "job.json": job} {
				if err := os.WriteFile(filepath.Join(directory, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "public" {
				if err := os.Mkdir(filepath.Join(root, "operator"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "recorded-wrong-parent" {
				mode, _ := json.Marshal(
					frozenExecution{
						Schema:            1,
						Local:             false,
						LockDirectory:     root,
						OperatorDirectory: filepath.Join(t.TempDir(), "operator"),
					},
				)
				if err := os.WriteFile(filepath.Join(filepath.Dir(directory), "execution-mode.json"), mode, 0600); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			if _, err := withFrozenBootstrapStageLease(context.Background(), directory, func(context.Context) (deployansible.Receipt, error) {
				called = true
				return deployansible.Receipt{}, nil
			}); err == nil ||
				called {
				t.Fatal("unproved original operator lock accepted")
			}
		})
	}
}
