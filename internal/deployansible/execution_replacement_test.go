package deployansible

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReplacementPreflightClassifiesOnlyExactFailedGeneration(t *testing.T) {
	for _, state := range []string{"none", "failed", "running", "missing", "malformed", "changed-request"} {
		t.Run(state, func(t *testing.T) {
			root, job := executionFixture(t)
			var fence *ExecutionFence
			if state != "none" {
				prepareExecutionFixture(t, job)
				var err error
				fence, err = beginExecution(job)
				if err != nil {
					t.Fatal(err)
				}
				if err = writeJSON(filepath.Join(job, "execution-dispatch-"+fence.Generation+".json"), fence); err != nil {
					t.Fatal(err)
				}
				if state != "missing" {
					receiptState := "failed"
					if state == "running" {
						receiptState = "running"
					}
					if err = writeJSON(filepath.Join(job, "receipt.json"), map[string]any{"state": receiptState, "execution_generation": fence.Generation}); err != nil {
						t.Fatal(err)
					}
				}
				if state == "malformed" {
					if err = os.WriteFile(filepath.Join(root, "execution-fence.json"), []byte("{"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if state == "changed-request" {
					if err = os.WriteFile(filepath.Join(job, "request.json"), []byte("{}"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			before := preflightSnapshot(t, root)
			got, err := PreflightExecutionReplacement()
			if state == "none" {
				if err != nil || got != nil {
					t.Fatal(got, err)
				}
			} else if state == "failed" {
				if err != nil || got == nil || *got != *fence {
					t.Fatal(got, err)
				}
			} else if !errors.Is(err, ErrExecutionFenced) {
				t.Fatalf("unsafe state %s accepted: %v", state, err)
			}
			if after := preflightSnapshot(t, root); !reflect.DeepEqual(before, after) {
				t.Fatal("classification changed preserved evidence")
			}
		})
	}
}
