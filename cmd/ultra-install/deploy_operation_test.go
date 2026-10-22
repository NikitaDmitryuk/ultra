package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func runFixtureDeployOperation(
	ctx context.Context,
	directory string,
	request deployOperationRequest,
	run func(context.Context, []string) error,
) error {
	return runDeployOperationWithFinalObservation(ctx, directory, request, run, func(context.Context, []string) error { return nil })
}

func deployOperationFixture(t *testing.T) (string, deployOperationRequest) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	request := deployOperationRequest{Schema: 1, Args: []string{"operator-upgrade", "--config", "/fixture/install.config"}}
	raw, _ := json.Marshal(request)
	if err := saveDeployOperation(filepath.Join(directory, "request.json"), request); err != nil {
		t.Fatal(err)
	}
	if err := saveDeployOperation(filepath.Join(directory, "state.json"), deployOperationState{1, digestSHA256(raw), "upgrade", "submitted", ""}); err != nil {
		t.Fatal(err)
	}
	return directory, request
}

func TestDeployOperationSuccessAndCompletedReplay(t *testing.T) {
	directory, request := deployOperationFixture(t)
	var calls []string
	run := func(_ context.Context, args []string) error { calls = append(calls, args[0]); return nil }
	for range 2 {
		if err := runFixtureDeployOperation(context.Background(), directory, request, run); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(calls, []string{"operator-upgrade", "status"}) {
		t.Fatalf("unexpected dispatch: %v", calls)
	}
}

func TestDeployOperationStatusRetryDoesNotRedispatchUpgrade(t *testing.T) {
	directory, request := deployOperationFixture(t)
	var calls []string
	run := func(_ context.Context, args []string) error {
		calls = append(calls, args[0])
		if len(calls) == 2 {
			return errors.New("synthetic status failure")
		}
		return nil
	}
	if err := runFixtureDeployOperation(context.Background(), directory, request, run); err == nil {
		t.Fatal("status failure accepted")
	}
	if err := runFixtureDeployOperation(context.Background(), directory, request, run); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls, []string{"operator-upgrade", "status", "status"}) {
		t.Fatalf("unexpected dispatch: %v", calls)
	}
}

func TestDeployOperationFailedOrOrphanedUpgradeNeverReplayed(t *testing.T) {
	for _, state := range []string{"running", "blocked"} {
		t.Run(state, func(t *testing.T) {
			directory, request := deployOperationFixture(t)
			saved, _ := readDeployOperation(directory, request)
			saved.State = state
			if state == "blocked" {
				saved.Reason = "deploy_operation_upgrade_failed"
			}
			if err := saveDeployOperation(filepath.Join(directory, "state.json"), saved); err != nil {
				t.Fatal(err)
			}
			err := runFixtureDeployOperation(context.Background(), directory, request, func(context.Context, []string) error {
				t.Fatal("uncertain upgrade replayed")
				return nil
			})
			if err == nil || err.Error() != "deploy_operation_execution_uncertain" {
				t.Fatalf("unexpected result: %v", err)
			}
		})
	}
}

func TestDeployOperationFailedUpgradeRetainsBlock(t *testing.T) {
	directory, request := deployOperationFixture(t)
	err := runFixtureDeployOperation(context.Background(), directory, request, func(context.Context, []string) error {
		return errors.New("synthetic failure")
	})
	if err == nil {
		t.Fatal("failed upgrade accepted")
	}
	state, err := readDeployOperation(directory, request)
	if err != nil || state.Stage != "upgrade" || state.State != "blocked" {
		t.Fatalf("missing block: %+v %v", state, err)
	}
}

func TestDeployOperationRejectsChangedInputsAndLinkedState(t *testing.T) {
	directory, request := deployOperationFixture(t)
	changed := deployOperationRequest{Schema: 1, Args: []string{"operator-upgrade", "--config", "/another/install.config"}}
	if _, err := readDeployOperation(directory, changed); err == nil {
		t.Fatal("changed request accepted")
	}
	statePath := filepath.Join(directory, "state.json")
	if err := os.Rename(statePath, statePath+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(statePath+".original", statePath); err != nil {
		t.Fatal(err)
	}
	if _, err := readDeployOperation(directory, request); err == nil {
		t.Fatal("linked state accepted")
	}
	if err := saveDeployOperation(statePath, map[string]any{}); err == nil {
		t.Fatal("linked publication accepted")
	}
}

func TestDeployOperationUnitOwnsCompleteProcessTree(t *testing.T) {
	args := strings.Join(deployUnitArgs(strings.Repeat("a", 64), "/candidate/ultra-install", "/operation"), " ")
	for _, required := range []string{"--property=KillMode=control-group", "--property=RemainAfterExit=yes", "--property=Restart=no", "deploy-operation run --directory /operation"} {
		if !strings.Contains(args, required) {
			t.Fatalf("unit lacks %s", required)
		}
	}
	if strings.Contains(args, "--scope") || strings.Contains(args, "--pty") {
		t.Fatal("unit remains tied to operator terminal")
	}
}

func TestDeployOperationAdmissionRejectsOtherCandidateUntilCompleted(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	request := deployOperationRequest{Schema: 1, Args: []string{"operator-upgrade", "--config", "/fixture/install.config"}}
	raw, _ := json.Marshal(request)
	identity := digestSHA256(raw)
	directory := filepath.Join(root, identity)
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveDeployOperation(filepath.Join(directory, "request.json"), request); err != nil {
		t.Fatal(err)
	}
	state := deployOperationState{1, identity, "upgrade", "running", ""}
	if err := saveDeployOperation(filepath.Join(directory, "state.json"), state); err != nil {
		t.Fatal(err)
	}
	if err := admitDeployOperation(root, identity); err != nil {
		t.Fatal(err)
	}
	if err := admitDeployOperation(root, strings.Repeat("b", 64)); err == nil {
		t.Fatal("different candidate admitted while original is running")
	}
	if err := admitDeployOperation(root, identity); err != nil {
		t.Fatal("same operation could not attach:", err)
	}
	state.Stage, state.State = "status", "completed"
	if err := saveDeployOperation(filepath.Join(directory, "state.json"), state); err != nil {
		t.Fatal(err)
	}
	if err := admitDeployOperation(root, strings.Repeat("b", 64)); err != nil {
		t.Fatal("completed operation prevented next candidate:", err)
	}
}

func TestDeployOperationExplicitRetryUsesSameRequest(t *testing.T) {
	directory, request := deployOperationFixture(t)
	state, err := readDeployOperation(directory, request)
	if err != nil {
		t.Fatal(err)
	}
	// Only CLI reconciliation can publish retry_prepared after proof validation.
	state.State = "retry_prepared"
	if err = saveDeployOperation(filepath.Join(directory, "state.json"), state); err != nil {
		t.Fatal(err)
	}
	if err = runFixtureDeployOperation(context.Background(), directory, request, func(_ context.Context, args []string) error {
		if args[0] == "operator-upgrade" && args[len(args)-1] != "--retry-failed" {
			t.Fatal("explicit recovery lost underlying upgrade preflight")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = readDeployOperation(directory, request); err != nil {
		t.Fatal("retry changed immutable request:", err)
	}
}

func TestDeployOperationResubmitAfterStatusCrashPreservesCompletedUpgrade(t *testing.T) {
	for _, interrupted := range []string{"prepared", "submitted", "running", "blocked"} {
		t.Run(interrupted, func(t *testing.T) {
			directory, request := deployOperationFixture(t)
			state, err := readDeployOperation(directory, request)
			if err != nil {
				t.Fatal(err)
			}
			state.Stage, state.State = "status", interrupted
			if interrupted == "blocked" {
				state.Reason = "deploy_operation_status_failed"
			}
			if err = saveDeployOperation(filepath.Join(directory, "state.json"), state); err != nil {
				t.Fatal(err)
			}
			if err = prepareDeploySubmission(directory, request, false); err == nil && interrupted != "prepared" {
				t.Fatal("unprepared status crash admitted without explicit retry")
			}
			if err = prepareDeploySubmission(directory, request, true); err != nil {
				t.Fatal(err)
			}
			if err = runFixtureDeployOperation(context.Background(), directory, request, func(_ context.Context, args []string) error {
				if args[0] != "status" {
					t.Fatalf("completed upgrade redispatched after status crash: %v", args)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeployOperationSubmissionCannotReauthorizeOrphanedUpgrade(t *testing.T) {
	directory, request := deployOperationFixture(t)
	state, err := readDeployOperation(directory, request)
	if err != nil {
		t.Fatal(err)
	}
	state.State = "running"
	if err = saveDeployOperation(filepath.Join(directory, "state.json"), state); err != nil {
		t.Fatal(err)
	}
	for _, restart := range []bool{false, true} {
		if err = prepareDeploySubmission(directory, request, restart); err == nil {
			t.Fatal("orphaned mutator admitted without completion evidence")
		}
	}
}

func deployPreparationFixture(t *testing.T, stage, execution string) (string, deployOperationRequest) {
	t.Helper()
	directory, request := deployOperationFixture(t)
	request.Schema = 2
	request.Preparation = &recoveryPreparationRequest{Protocol: "fixture"}
	raw, _ := json.Marshal(request)
	if err := saveDeployOperation(filepath.Join(directory, "request.json"), request); err != nil {
		t.Fatal(err)
	}
	state := deployOperationState{1, digestSHA256(raw), stage, execution, ""}
	if execution == "blocked" {
		state.Reason = "deploy_operation_" + stage + "_failed"
	}
	if err := saveDeployOperation(filepath.Join(directory, "state.json"), state); err != nil {
		t.Fatal(err)
	}
	return directory, request
}

func TestDeployOperationPreparationRunsInOrderAndAdvancesBeforeDispatch(t *testing.T) {
	directory, request := deployPreparationFixture(t, deployPreparationPhases[0], "submitted")
	var calls []string
	prepare := func(_ context.Context, phase string, _ recoveryPreparationRequest, args []string) error {
		state, err := readDeployOperation(directory, request)
		if err != nil || state.Stage != phase || state.State != "running" {
			t.Fatalf("dispatch without durable ownership: %+v %v", state, err)
		}
		if !reflect.DeepEqual(args, request.Args) {
			t.Fatalf("unexpected retry: %v", args)
		}
		calls = append(calls, phase)
		return nil
	}
	run := func(_ context.Context, args []string) error { calls = append(calls, args[0]); return nil }
	observe := func(context.Context, string, recoveryPreparationRequest, []string) error {
		t.Fatal("unexpected recovery observation")
		return nil
	}
	if err := runDeployOperationPhases(context.Background(), directory, request, run, prepare, observe); err != nil {
		t.Fatal(err)
	}
	want := append(append([]string{}, deployPreparationPhases...), "operator-upgrade", "status")
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("phase order: %v", calls)
	}
}

func TestDeployOperationInterruptedPreparationRequiresExactTerminalObservation(t *testing.T) {
	for _, phase := range deployPreparationPhases {
		for _, terminal := range []bool{false, true} {
			t.Run(phase+"/"+strconv.FormatBool(terminal), func(t *testing.T) {
				directory, request := deployPreparationFixture(t, phase, "running")
				observed := false
				prepare := func(_ context.Context, next string, _ recoveryPreparationRequest, _ []string) error {
					if next == phase || !observed {
						t.Fatal("interrupted mutation dispatched again")
					}
					return nil
				}
				observe := func(_ context.Context, current string, _ recoveryPreparationRequest, _ []string) error {
					if current != phase {
						t.Fatalf("wrong observation: %s", current)
					}
					observed = true
					if !terminal {
						return errors.New("no exact completion")
					}
					return nil
				}
				calls := 0
				err := runDeployOperationPhases(
					context.Background(),
					directory,
					request,
					func(context.Context, []string) error { calls++; return nil },
					prepare,
					observe,
				)
				if terminal {
					if err != nil || calls != 2 {
						t.Fatalf("confirmed completion not recovered: %v %d", err, calls)
					}
				} else if err == nil || calls != 0 {
					t.Fatalf("uncertain completion dispatched: %v %d", err, calls)
				}
			})
		}
	}
}

func TestDeployOperationPreparationRetryPreservesFrozenRequest(t *testing.T) {
	directory, request := deployPreparationFixture(t, "tools_staged", "blocked")
	if err := prepareDeploySubmission(directory, request, true); err != nil {
		t.Fatal(err)
	}
	first := true
	err := runDeployOperationPhases(context.Background(), directory, request, func(context.Context, []string) error { return nil },
		func(_ context.Context, phase string, _ recoveryPreparationRequest, args []string) error {
			_, retry := cleanDeployRetry(args)
			if retry != first {
				t.Fatalf("retry spread to another phase: %s %v", phase, args)
			}
			first = false
			return nil
		}, func(context.Context, string, recoveryPreparationRequest, []string) error {
			t.Fatal("explicit retry observed instead of gated dispatch")
			return nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := readDeployOperation(directory, request); err != nil {
		t.Fatal("frozen request changed", err)
	}
}

func TestDeployOperationReconcilePreparationDoesNotRunNextPhase(t *testing.T) {
	for _, verified := range []bool{false, true} {
		t.Run(strconv.FormatBool(verified), func(t *testing.T) {
			directory, request := deployPreparationFixture(t, "monitor_initialized", "blocked")
			state, err := reconcileDeployPreparationCheckpoint(context.Background(), directory, request,
				func(_ context.Context, phase string, _ recoveryPreparationRequest, _ []string) error {
					if phase != "monitor_initialized" {
						t.Fatalf("observing wrong phase: %s", phase)
					}
					if !verified {
						return errors.New("terminal evidence missing")
					}
					return nil
				})
			if verified {
				if err != nil || state.Stage != "recovery_reconciled" || state.State != "prepared" {
					t.Fatalf("checkpoint not persisted: %+v %v", state, err)
				}
			} else {
				if err == nil {
					t.Fatal("unproven phase closed")
				}
				saved, readErr := readDeployOperation(directory, request)
				if readErr != nil || saved.Stage != "monitor_initialized" || saved.State != "blocked" {
					t.Fatalf("failed observation changed admission: %+v %v", saved, readErr)
				}
			}
		})
	}
}

func TestDeployOperationHandoffMetadataResumeCannotRedispatchMutation(t *testing.T) {
	for _, interrupted := range []string{"running", "retry_prepared"} {
		for _, accepted := range []bool{false, true} {
			t.Run(interrupted+"/"+strconv.FormatBool(accepted), func(t *testing.T) {
				directory, request := deployPreparationFixture(t, "broker_handoff", interrupted)
				metadata := false
				dispatches := 0
				resumes := 0
				err := runDeployOperationSteps(context.Background(), directory, request,
					func(context.Context, []string) error { dispatches++; return nil },
					func(context.Context, string, recoveryPreparationRequest, []string) error {
						t.Fatal("handoff mutation job redispatched")
						return nil
					},
					func(context.Context, string, recoveryPreparationRequest, []string) error {
						if metadata {
							return nil
						}
						return errors.New("handoff metadata incomplete")
					},
					func(_ context.Context, phase string, _ recoveryPreparationRequest, args []string) error {
						resumes++
						state, e := readDeployOperation(directory, request)
						if e != nil || state.State != "running" || state.Stage != "broker_handoff" || phase != "broker_handoff" {
							t.Fatalf("metadata action not supervised: %+v %v", state, e)
						}
						if !reflect.DeepEqual(args, request.Args) {
							t.Fatal("metadata action changed immutable arguments")
						}
						if !accepted {
							return errors.New("normal terminal proof unavailable")
						}
						metadata = true
						return nil
					})
				if resumes != 1 {
					t.Fatalf("metadata attempts: %d", resumes)
				}
				if accepted {
					if err != nil || dispatches != 2 {
						t.Fatalf("verified metadata not completed: %v %d", err, dispatches)
					}
				} else if err == nil || dispatches != 0 {
					t.Fatalf("unproven metadata advanced operation: %v %d", err, dispatches)
				}
			})
		}
	}
}

func TestDeployOperationFinalProducerRunsForBothSchemasAndStatusRetry(t *testing.T) {
	for _, schema := range []int{1, 2} {
		t.Run(strconv.Itoa(schema), func(t *testing.T) {
			directory, request := deployOperationFixture(t)
			if schema == 2 {
				directory, request = deployPreparationFixture(t, "upgrade", "prepared")
			}
			calls := []string{}
			run := func(_ context.Context, args []string) error { calls = append(calls, args[0]); return nil }
			observations := 0
			reconcile := func(_ context.Context, args []string) error {
				state, err := readDeployOperation(directory, request)
				if err != nil || state.Stage != "status" || state.State != "running" || !reflect.DeepEqual(args, request.Args) {
					t.Fatalf("producer outside status ownership: %+v %v", state, err)
				}
				observations++
				calls = append(calls, "postactivation")
				if observations == 1 {
					return errors.New("synthetic stale evidence")
				}
				return nil
			}
			if err := runDeployOperationWithFinalObservation(context.Background(), directory, request, run, reconcile); err == nil {
				t.Fatal("missing readiness accepted")
			}
			if err := runDeployOperationWithFinalObservation(context.Background(), directory, request, run, reconcile); err != nil {
				t.Fatal(err)
			}
			if want := []string{"operator-upgrade", "postactivation", "postactivation", "status"}; !reflect.DeepEqual(calls, want) {
				t.Fatalf("dispatch: %v", calls)
			}
		})
	}
}
