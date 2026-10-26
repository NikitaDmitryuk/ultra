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
	"syscall"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type failedReplacementFixture struct {
	root    string
	fence   deployansible.ExecutionFence
	plan    *installplan.InstallPlan
	primary replacementPrimary
	scope   *replacementExecutionScope
}

func writeExecutionFixtureJSON(t *testing.T, path string, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return raw
}
func replacementFailedFixture(t *testing.T) failedReplacementFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	savedResolver := fixtureExecutionNamespace
	fixtureExecutionNamespace = func(string) string { return root }
	t.Cleanup(func() { fixtureExecutionNamespace = savedResolver })
	state := filepath.Join(t.TempDir(), "replacement-old")
	job := filepath.Join(state, "bootstrap", "bootstrap-"+strings.Repeat("a", 64), "attempt-123", "controller-prepare-456")
	if err := os.MkdirAll(filepath.Join(job, "bundle"), 0700); err != nil {
		t.Fatal(err)
	}
	p := &installplan.InstallPlan{
		SSH:    installplan.SSHConfig{User: "root", Identity: "/keys/operator"},
		Bridge: installplan.BridgeConfig{Address: "192.0.2.10", SSHHost: "192.0.2.10"},
		Exits:  []installplan.ExitNode{{Name: "main", SSHHost: "192.0.2.20"}},
		Database: installplan.DatabaseConfig{
			Enabled:     true,
			PrimaryHost: "192.0.2.30",
			Name:        "fixture",
			SSHUser:     "root",
			SSHIdentity: "/keys/database",
		},
		Automation: &installplan.AutomationConfig{KnownHostsFile: "/pins/current"},
	}
	commonArgs := "-F /dev/null -o ControlMaster=no -o ControlPath=none -o UpdateHostKeys=no -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + shellQuote(
		p.Automation.KnownHostsFile,
	)
	raw := writeExecutionFixtureJSON(
		t,
		filepath.Join(job, "request.json"),
		map[string]any{
			"inventory": map[string]any{
				"all": map[string]any{
					"vars": map[string]any{
						"ansible_user":                 "root",
						"ansible_ssh_private_key_file": "/keys/operator",
						"ansible_ssh_common_args":      commonArgs,
						"ultra_db_tunnel_host":         p.Database.PrimaryHost,
					},
					"children": map[string]any{
						"bridge": map[string]any{"hosts": map[string]any{"bridge": map[string]any{"ansible_host": p.Bridge.SSHHost}}},
						"exits":  map[string]any{"hosts": map[string]any{"exit_0": map[string]any{"ansible_host": p.Exits[0].SSHHost}}},
						"databases": map[string]any{
							"hosts": map[string]any{
								"database": map[string]any{
									"ansible_host":                 p.Database.PrimaryHost,
									"ansible_ssh_private_key_file": "/keys/database",
								},
							},
						},
					},
				},
			},
			"variables": map[string]any{},
		},
	)
	jobRaw := writeExecutionFixtureJSON(
		t,
		filepath.Join(job, "job.json"),
		map[string]any{
			"schema_version": 1,
			"operation":      "prepare-controller",
			"request_sha256": digestSHA256(raw),
			"binary_sha256":  digestSHA256(raw),
		},
	)
	bundle := []byte("# immutable source\n")
	if err := os.WriteFile(filepath.Join(job, "bundle/controller.py"), bundle, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte("controller.py\x00" + digestSHA256(bundle) + "\n"))
	fence := deployansible.ExecutionFence{
		SchemaVersion:   1,
		Generation:      strings.Repeat("b", 32),
		Operation:       "prepare-controller",
		JobDirectory:    job,
		JobSHA256:       digestSHA256(jobRaw),
		RequestSHA256:   digestSHA256(raw),
		BundleSHA256:    hex.EncodeToString(hash[:]),
		InventorySHA256: digestSHA256(raw),
		Attempt:         1,
	}
	writeExecutionFixtureJSON(t, filepath.Join(root, "execution-fence.json"), fence)
	writeExecutionFixtureJSON(t, filepath.Join(job, "execution-dispatch-"+fence.Generation+".json"), fence)
	writeExecutionFixtureJSON(
		t,
		filepath.Join(job, "receipt.json"),
		map[string]any{"state": "failed", "execution_generation": fence.Generation, "code": "ansible_failed"},
	)
	primary := replacementPrimary{
		SystemIdentifier: "12345",
		Database:         "fixture",
		DatabaseOID:      42,
		Migrations:       "1,2",
		Routes: []exits.BootstrapEntry{
			{Name: "main", Address: "192.0.2.20", TunnelUUID: "fixture-uuid", PinnedPeerCertSHA256: strings.Repeat("a", 64), Priority: 100},
		},
	}
	writeExecutionFixtureJSON(t, filepath.Join(state, "primary-before.json"), primary)
	targets, err := replacementTargets(p)
	if err != nil {
		t.Fatal(err)
	}
	writeExecutionFixtureJSON(t, filepath.Join(state, "targets.json"), targets)
	scope, err := validateReplacementExecutionScope(fence, p, []*installplan.InstallPlan{p})
	if err != nil {
		t.Fatal(err)
	}
	return failedReplacementFixture{root, fence, p, primary, scope}
}

func TestFailedExecutionReplacementRunsRealRetirementBeforeCleanup(t *testing.T) {
	for _, failure := range []string{"", "active-unit", "active-process", "remote", "primary", "scope-changed", "generation-changed"} {
		t.Run(failure, func(t *testing.T) {
			f := replacementFailedFixture(t)
			originalReceipt, err := os.ReadFile(filepath.Join(f.fence.JobDirectory, "receipt.json"))
			if err != nil {
				t.Fatal(err)
			}
			originalDispatch, err := os.ReadFile(filepath.Join(f.fence.JobDirectory, "execution-dispatch-"+f.fence.Generation+".json"))
			if err != nil {
				t.Fatal(err)
			}
			binding := deployansible.ReplacementBinding{
				Workspace:     filepath.Join(f.root, "replacement-new"),
				TargetsSHA256: strings.Repeat("a", 64),
				PrimarySHA256: strings.Repeat("b", 64),
			}
			ctx, reservation, reserveErr := deployansible.ReserveReplacement(context.Background(), binding, nil)
			if reserveErr != nil {
				t.Fatal(reserveErr)
			}
			defer func() { _ = reservation.Close() }()
			defer func() { _ = reservation.Finish() }()
			competingDispatch := func() {
				directory := filepath.Join(f.root, "other-private-state", "operation")
				_, dispatchErr := deployansible.RunLocal(
					context.Background(),
					"bootstrap",
					map[string]any{},
					map[string]any{},
					directory,
					"/usr/bin/python3",
					"/bin/false",
				)
				if !errors.Is(dispatchErr, deployansible.ErrReplacementReserved) {
					t.Fatalf("competing real dispatch during replacement: %v", dispatchErr)
				}
				if _, err := os.Stat(filepath.Join(directory, "execution-generation.json")); !os.IsNotExist(err) {
					t.Fatal("competing dispatch published generation", err)
				}
			}
			targets, _ := replacementTargets(f.plan)
			var events []string
			prepared := false
			localCalls := 0
			cleaned := false
			steps := replacementSteps{
				Checkpoint: func(stage string) error { events = append(events, stage); return nil },
				Observe: func(context.Context) (replacementPrimary, error) {
					value := f.primary
					if prepared && failure == "primary" {
						value.Migrations = "changed"
					}
					return value, nil
				},
				Discover: func(context.Context, replacementTarget) error { return nil },
				Fence:    func(context.Context, replacementTarget) error { prepared = true; return nil },
				Quiescent: func(context.Context, replacementTarget) error {
					if failure == "remote" {
						return errors.New("remote_not_quiescent")
					}
					return nil
				},
				PrimaryQuiescent: func(context.Context) error { return nil },
				Clean: func(context.Context, replacementTarget, []exits.BootstrapEntry) error {
					cleaned = true
					competingDispatch()
					if _, err := os.Stat(filepath.Join(f.root, "execution-fence.json")); !os.IsNotExist(err) {
						t.Fatal("cleanup began before old fence retirement")
					}
					if _, err := os.Stat(filepath.Join(f.fence.JobDirectory, "execution-abandonment.json")); err != nil {
						t.Fatal("retirement evidence missing", err)
					}
					return nil
				},
				RetireJournal: func() error { return nil },
				Bootstrap: func(context.Context) error {
					competingDispatch()
					next, err := deployansible.PreflightExecutionReplacement()
					if err != nil || next != nil {
						t.Fatal("corrected fresh attempt remained blocked", next, err)
					}
					return nil
				},
			}
			localProof := func(deployansible.ExecutionFence) error {
				localCalls++
				// The real API must own the global admission lock during every proof.
				fd, err := os.OpenFile(filepath.Join(f.root, "execution-admission.lock"), os.O_RDWR, 0600)
				if err != nil {
					t.Fatal(err)
				}
				err = syscall.Flock(int(fd.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
				_ = fd.Close()
				if err == nil {
					t.Fatal("retirement proof ran outside admission lock")
				}
				if strings.HasPrefix(failure, "active-") {
					return errors.New("active_executor")
				}
				if localCalls == 2 && failure == "scope-changed" {
					if err := os.WriteFile(filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(f.fence.JobDirectory)))), "primary-before.json"), []byte("{}"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if localCalls == 2 && failure == "generation-changed" {
					changed := f.fence
					changed.Generation = strings.Repeat("c", 32)
					writeExecutionFixtureJSON(t, filepath.Join(f.root, "execution-fence.json"), changed)
				}
				return nil
			}
			steps.AdmitFailedExecution = admitReplacementFailedExecutionWithProof(f.fence, f.scope, f.primary, steps, localProof)
			err = executeProductionReplacement(ctx, targets, f.primary, steps)
			if localCalls == 0 {
				t.Fatal("failure did not reach actual retirement proof", err)
			}
			if failure == "" {
				if err != nil || !cleaned || localCalls != 2 {
					t.Fatal(err, events, localCalls)
				}
				receipt, err := os.ReadFile(filepath.Join(f.fence.JobDirectory, "receipt.json"))
				if err != nil || string(receipt) != string(originalReceipt) {
					t.Fatal("original receipt changed", err)
				}
				dispatch, err := os.ReadFile(filepath.Join(f.fence.JobDirectory, "execution-dispatch-"+f.fence.Generation+".json"))
				if err != nil || string(dispatch) != string(originalDispatch) {
					t.Fatal("original dispatch changed", err)
				}
			} else {
				if err == nil || cleaned {
					t.Fatal("unsafe replacement admitted", failure, events)
				}
				if strings.HasPrefix(failure, "active-") && prepared {
					t.Fatal("active executor caused teardown")
				}
				if _, err = os.Stat(filepath.Join(f.root, "execution-fence.json")); err != nil {
					t.Fatal("unsafe fence retired", err)
				}
			}
		})
	}
}

func TestFailedExecutionScopeRejectsUnknownTargetsAndPrimaryChanges(t *testing.T) {
	f := replacementFailedFixture(t)
	changed := *f.plan
	changed.Exits = append([]installplan.ExitNode(nil), f.plan.Exits...)
	changed.Exits[0].SSHHost = "192.0.2.99"
	if _, err := validateReplacementExecutionScope(f.fence, &changed, []*installplan.InstallPlan{&changed}); err == nil {
		t.Fatal("unretained old target accepted")
	}
	if _, err := validateReplacementExecutionScope(f.fence, &changed, []*installplan.InstallPlan{&changed, f.plan}); err != nil {
		t.Fatal("explicitly retained target rejected", err)
	}
	for _, change := range []func(*replacementPrimary){func(p *replacementPrimary) { p.SystemIdentifier = "foreign" }, func(p *replacementPrimary) { p.DatabaseOID++ }, func(p *replacementPrimary) { p.Database = "other" }} {
		p := f.primary
		change(&p)
		if err := f.scope.verifyPrimary(p); err == nil {
			t.Fatal("changed primary accepted")
		}
	}
	unknown := f.fence
	unknown.Operation = "configure-exit"
	if _, err := validateReplacementExecutionScope(unknown, f.plan, []*installplan.InstallPlan{f.plan}); err == nil {
		t.Fatal("unrelated worker operation accepted")
	}
}

func TestFailedExecutionChangedEvidenceCannotReachTeardown(t *testing.T) {
	for _, state := range []string{"malformed", "running", "missing", "request"} {
		t.Run(state, func(t *testing.T) {
			f := replacementFailedFixture(t)
			switch state {
			case "malformed":
				if err := os.WriteFile(filepath.Join(f.root, "execution-fence.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "running":
				writeExecutionFixtureJSON(
					t,
					filepath.Join(f.fence.JobDirectory, "receipt.json"),
					map[string]any{"state": "running", "execution_generation": f.fence.Generation},
				)
			case "missing":
				if err := os.Remove(filepath.Join(f.fence.JobDirectory, "receipt.json")); err != nil {
					t.Fatal(err)
				}
			case "request":
				if err := os.WriteFile(filepath.Join(f.fence.JobDirectory, "request.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			called := false
			admit := admitReplacementFailedExecutionWithProof(
				f.fence,
				f.scope,
				f.primary,
				replacementSteps{},
				func(deployansible.ExecutionFence) error { called = true; return nil },
			)
			if err := admit(context.Background(), func() error { called = true; return nil }); err == nil || called {
				t.Fatal("changed evidence reached proof or teardown", err)
			}
		})
	}
}

func TestFailedExecutionAdmissionLockExcludesConcurrentRetirement(t *testing.T) {
	f := replacementFailedFixture(t)
	scope := f.scope
	// The outer real retirement owns the global lock while preparation runs.
	admit := admitReplacementFailedExecutionWithProof(
		f.fence,
		scope,
		f.primary,
		replacementSteps{
			Observe:          func(context.Context) (replacementPrimary, error) { return f.primary, nil },
			PrimaryQuiescent: func(context.Context) error { return nil },
		},
		func(deployansible.ExecutionFence) error { return nil },
	)
	err := admit(context.Background(), func() error {
		result := make(chan error, 1)
		go func() {
			result <- deployansible.AbandonExecutionFence(f.fence, func(deployansible.ExecutionFence) error { t.Error("competing retirement entered proof"); return nil })
		}()
		if err := <-result; !errors.Is(err, deployansible.ErrExecutionFenced) {
			t.Fatalf("concurrent retirement was admitted: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReplacementReservationScopeBindsExactCrashedParent(t *testing.T) {
	f := replacementFailedFixture(t)
	state, err := replacementExecutionState(f.fence.JobDirectory)
	if err != nil {
		t.Fatal(err)
	}
	targetsRaw, err := os.ReadFile(filepath.Join(state, "targets.json"))
	if err != nil {
		t.Fatal(err)
	}
	primaryRaw, err := os.ReadFile(filepath.Join(state, "primary-before.json"))
	if err != nil {
		t.Fatal(err)
	}
	record := deployansible.ReplacementReservation{
		Binding: deployansible.ReplacementBinding{
			Workspace:     state,
			TargetsSHA256: digestSHA256(targetsRaw),
			PrimarySHA256: digestSHA256(primaryRaw),
		},
	}
	for _, change := range []string{"none", "targets-hash", "primary-hash", "primary-identity", "target-not-retained"} {
		t.Run(change, func(t *testing.T) {
			actual := record
			before := f.primary
			plan := *f.plan
			switch change {
			case "targets-hash":
				actual.Binding.TargetsSHA256 = strings.Repeat("f", 64)
			case "primary-hash":
				actual.Binding.PrimarySHA256 = strings.Repeat("f", 64)
			case "primary-identity":
				before.SystemIdentifier = "different"
			case "target-not-retained":
				plan.Bridge.SSHHost = "192.0.2.99"
				plan.Bridge.Address = "192.0.2.99"
			}
			err := validateReplacementReservationScope(actual, &plan, []*installplan.InstallPlan{&plan}, before)
			if (err == nil) != (change == "none") {
				t.Fatalf("%s: %v", change, err)
			}
		})
	}
}
