package deployansible

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSetExecutionStateEnvironmentReplacesInheritedValue(t *testing.T) {
	got := setExecutionStateEnvironment([]string{"PATH=/bin", "ULTRA_OPERATOR_STATE_DIRECTORY=/wrong", "LANG=C"}, "/home/operator/.local/state/ultra-ansible")
	want := []string{"PATH=/bin", "LANG=C", "ULTRA_OPERATOR_STATE_DIRECTORY=/home/operator/.local/state/ultra-ansible"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("execution state environment = %v, want %v", got, want)
	}
}

func containmentCompletionFixture(t *testing.T) (*ExecutionFence, containmentProof) {
	t.Helper()
	_, job := executionFixture(t)
	prepareExecutionFixture(t, job)
	fence, err := beginExecution(job)
	if err != nil {
		t.Fatal(err)
	}
	receipt := map[string]any{"state": "succeeded", "execution_generation": fence.Generation}
	if err = writeJSON(filepath.Join(job, "receipt.json"), receipt); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(job, "receipt.json"))
	if err = writeJSON(filepath.Join(job, "execution-completion.json"), map[string]any{"fence": fence, "local_cleanup": true, "receipt_sha256": executionHash(raw)}); err != nil {
		t.Fatal(err)
	}
	proof := containmentProof{
		Schema:       1,
		Fence:        *fence,
		Mode:         "transient",
		Unit:         "ultra-execution-" + fence.Generation + ".service",
		InvocationID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	proof.Chain = []containmentProcess{
		{
			PID:              123,
			Parent:           1,
			Starttime:        "99",
			Group:            "/system.slice/" + proof.Unit,
			ExecutableSHA256: strings.Repeat("a", 64),
			ArgvSHA256:       strings.Repeat("b", 64),
		},
	}
	if err = writeJSON(filepath.Join(job, "execution-containment.json"), proof); err != nil {
		t.Fatal(err)
	}
	return fence, proof
}
func mockContainmentObservation(t *testing.T, observe func(string) (map[string]string, error)) {
	t.Helper()
	old := observeContainmentUnit
	observeContainmentUnit = observe
	t.Cleanup(func() { observeContainmentUnit = old })
}
func TestContainmentDrainFailureCannotRetireNormalCompletion(t *testing.T) {
	fence, proof := containmentCompletionFixture(t)
	failure := errors.New("execution_containment_stop_unverified")
	mockContainmentObservation(t, func(string) (map[string]string, error) { return nil, failure })
	runErr := completeContainedExecution(*fence, proof.Unit, nil, func(string) error { return failure })
	if !errors.Is(runErr, failure) {
		t.Fatal(runErr)
	}
	if err := reconcileControllerExecution(*fence, runErr); !errors.Is(err, ErrExecutionFenced) {
		t.Fatal(err)
	}
	if err := ReconcileExecutionFence(*fence); !errors.Is(err, ErrExecutionFenced) {
		t.Fatal(err)
	}

	current, err := InspectExecutionFence()
	if err != nil || current == nil || *current != *fence {
		t.Fatal(current, err)
	}
	if _, err = os.Stat(filepath.Join(fence.JobDirectory, "execution-drain-"+fence.Generation+".json")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
func TestContainmentCompletionCrashBeforeDrainReceiptCanReconcile(t *testing.T) {
	fence, proof := containmentCompletionFixture(t)
	mockContainmentObservation(t, func(unit string) (map[string]string, error) {
		if unit != proof.Unit {
			t.Fatal(unit)
		}
		return map[string]string{"LoadState": "not-found"}, nil
	})
	if err := ReconcileExecutionFence(*fence); err != nil {
		t.Fatal(err)
	}
	current, err := InspectExecutionFence()
	if err != nil || current != nil {
		t.Fatal(current, err)
	}
}
func TestContainmentConfirmedDrainPreservesNormalFailureExit(t *testing.T) {
	fence, proof := containmentCompletionFixture(t)
	for _, name := range []string{"receipt.json", "execution-completion.json"} {
		if err := os.Remove(filepath.Join(fence.JobDirectory, name)); err != nil {
			t.Fatal(err)
		}
	}
	terminal := map[string]any{
		"fence":             fence,
		"outcome":           "failed",
		"contacted_hosts":   1,
		"pending_tasks":     0,
		"unreachable_hosts": 0,
		"unmanaged_async":   false,
	}
	terminalPath := filepath.Join(fence.JobDirectory, "execution-terminal-"+fence.Generation+".json")
	if err := writeJSON(terminalPath, terminal); err != nil {
		t.Fatal(err)
	}
	terminalRaw, _ := os.ReadFile(terminalPath)
	if err := writeJSON(filepath.Join(fence.JobDirectory, "receipt.json"), map[string]any{"state": "failed", "code": "ansible_failed", "exit_code": 2, "execution_generation": fence.Generation}); err != nil {
		t.Fatal(err)
	}
	receiptRaw, _ := os.ReadFile(filepath.Join(fence.JobDirectory, "receipt.json"))
	if err := writeJSON(filepath.Join(fence.JobDirectory, "execution-completion.json"), map[string]any{"fence": fence, "outcome": "failed", "local_cleanup": true, "receipt_sha256": executionHash(receiptRaw), "terminal_sha256": executionHash(terminalRaw)}); err != nil {
		t.Fatal(err)
	}
	normalRC2 := errors.New("exit status 2")
	if err := completeContainedExecution(*fence, proof.Unit, normalRC2, func(string) error { return nil }); !errors.Is(err, normalRC2) {
		t.Fatal(err)
	}
	mockContainmentObservation(t, func(string) (map[string]string, error) { return map[string]string{"ActiveState": "inactive"}, nil })
	if err := ReconcileExecutionFence(*fence); err != nil {
		t.Fatal(err)
	}
	if !completedExecution(fence.JobDirectory) {
		t.Fatal("normal rc2 completion rejected")
	}
	if err := prepareRetryExecution(fence.JobDirectory); err != nil {
		t.Fatalf("normal failed attempt cannot prepare exact retry: %v", err)
	}

}
func TestContainmentActiveTransientOrNewReuseOwnerCannotReconcile(t *testing.T) {
	for _, mode := range []string{"transient", "reuse"} {
		t.Run(mode, func(t *testing.T) {
			fence, proof := containmentCompletionFixture(t)
			if mode == "reuse" {
				proof.Mode = mode
				proof.Unit = "ultra-ansible-controller.service"
				proof.Chain[0].Group = "/system.slice/" + proof.Unit
			}
			mockContainmentObservation(t, func(string) (map[string]string, error) {
				return map[string]string{
					"LoadState":    "loaded",
					"ActiveState":  "active",
					"ControlGroup": "/system.slice/" + proof.Unit,
					"KillMode":     "control-group",
					"Delegate":     "no",
					"MainPID":      "456",
					"InvocationID": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
				}, nil
			})
			if err := verifyContainmentProof(proof); !errors.Is(err, ErrExecutionFenced) {
				t.Fatal(err)
			}
			_ = fence
		})
	}
}

func TestContainmentDrainReceiptCrashCloseAfterOwnerRestart(t *testing.T) {
	fence, proof := containmentCompletionFixture(t)
	// Actual drain has completed and receipt is durable, fence unlink crashes.
	if err := completeContainedExecution(*fence, proof.Unit, nil, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	mockContainmentObservation(t, func(string) (map[string]string, error) {
		t.Fatal("committed cleanup must not depend on later owner")
		return nil, nil
	})
	if err := ReconcileExecutionFence(*fence); err != nil {
		t.Fatal(err)
	}
	if !completedExecution(fence.JobDirectory) {
		t.Fatal("historical completion lost after owner restart")
	}
}

func TestContainmentReuseCensusAcceptsOnlyExactLiveAncestry(t *testing.T) {
	fence, proof := containmentCompletionFixture(t)
	proof.Mode = "reuse"
	proof.Unit = "ultra-ansible-controller.service"
	owner := containmentProcess{
		PID:              101,
		Parent:           1,
		Starttime:        "10",
		Group:            "/system.slice/" + proof.Unit,
		ExecutableSHA256: strings.Repeat("a", 64),
		ArgvSHA256:       strings.Repeat("b", 64),
	}
	dispatcher := owner
	dispatcher.PID = 202
	dispatcher.Parent = 101
	dispatcher.Starttime = "20"
	python := owner
	python.PID = 303
	python.Parent = 202
	python.Starttime = "30"
	proof.Chain = []containmentProcess{python, dispatcher, owner}
	mockContainmentObservation(t, func(string) (map[string]string, error) {
		return map[string]string{
			"LoadState":    "loaded",
			"ActiveState":  "active",
			"ControlGroup": owner.Group,
			"KillMode":     "control-group",
			"Delegate":     "no",
			"MainPID":      "101",
			"InvocationID": proof.InvocationID,
		}, nil
	})
	oldProcess, oldMembers := observeContainmentProcess, observeContainmentMembers
	t.Cleanup(func() { observeContainmentProcess = oldProcess; observeContainmentMembers = oldMembers })
	members := []int{101, 202, 404}
	identities := map[int]containmentProcess{101: owner, 202: dispatcher}
	observeContainmentProcess = func(pid int) (containmentProcess, error) {
		member, ok := identities[pid]
		if !ok {
			return containmentProcess{}, os.ErrNotExist
		}
		return member, nil
	}
	observeContainmentMembers = func(string) ([]int, error) { return members, nil }
	if err := verifyContainmentProof(proof); err == nil {
		t.Fatal("escaped worker was accepted")
	}
	members = []int{101, 202}
	if err := verifyContainmentProof(proof); err != nil {
		t.Fatal(err)
	}
	reused := owner
	reused.Starttime = "11"
	identities[101] = reused
	if err := verifyContainmentProof(proof); err == nil {
		t.Fatal("reused owner PID was accepted")
	}
	_ = fence
}

func TestContainmentVerifiedReceiptRejectsCompletionDrift(t *testing.T) {
	fence, proof := containmentCompletionFixture(t)
	if err := completeContainedExecution(*fence, proof.Unit, nil, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fence.JobDirectory, "execution-completion.json")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = file.Write([]byte(" ")); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if err = ReconcileExecutionFence(*fence); !errors.Is(err, ErrExecutionFenced) {
		t.Fatal(err)
	}
}

func TestContainmentReuseCrashCloseBeforeAndAfterDrainReceipt(t *testing.T) {
	for _, committed := range []bool{false, true} {
		t.Run(map[bool]string{false: "before-receipt", true: "after-receipt"}[committed], func(t *testing.T) {
			fence, proof := containmentCompletionFixture(t)
			proof.Mode = "reuse"
			proof.Unit = "ultra-ansible-controller.service"
			proof.Chain[0].Group = "/system.slice/" + proof.Unit
			path := filepath.Join(fence.JobDirectory, "execution-containment.json")
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := writeJSON(path, proof); err != nil {
				t.Fatal(err)
			}
			mockContainmentObservation(t, func(string) (map[string]string, error) {
				return map[string]string{"LoadState": "loaded", "ActiveState": "inactive"}, nil
			})
			if committed {
				if err := reconcileExecutionContainment(*fence); err != nil {
					t.Fatal(err)
				}
				// Crash after receipt fsync, before unlink. New same-name unit has a new
				// owner, but cannot invalidate already-proven old-generation quiescence.
				observeContainmentUnit = func(string) (map[string]string, error) {
					t.Fatal("already committed cleanup was reobserved")
					return nil, nil
				}
			}
			if err := ReconcileExecutionFence(*fence); err != nil {
				t.Fatal(err)
			}
		})
	}
}
