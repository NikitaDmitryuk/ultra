package deployansible

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func preflightSnapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	snapshot := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if !d.IsDir() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += "/" + executionHash(raw)
		}
		snapshot[relative] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestPreflightRejectsUnresolvedAdmissionWithoutChangingEvidence(t *testing.T) {
	for _, state := range []string{"absent", "present", "malformed", "queued-failed", "queued-malformed", "queued-read-only", "abandoned"} {
		t.Run(state, func(t *testing.T) {
			root, job := executionFixture(t)
			switch state {
			case "present", "abandoned":
				prepareExecutionFixture(t, job)
				fence, err := beginExecution(job)
				if err != nil {
					t.Fatal(err)
				}
				if state == "abandoned" {
					if err = writeJSON(filepath.Join(job, "receipt.json"), map[string]any{"state": "failed", "execution_generation": fence.Generation}); err != nil {
						t.Fatal(err)
					}
					if err = writeJSON(filepath.Join(job, "execution-dispatch-"+fence.Generation+".json"), fence); err != nil {
						t.Fatal(err)
					}
					if err = AbandonExecutionFence(*fence, func(ExecutionFence) error { return nil }); err != nil {
						t.Fatal(err)
					}
				}
			case "malformed":
				if err := writePrivate(filepath.Join(root, "execution-fence.json"), []byte("{")); err != nil {
					t.Fatal(err)
				}
			case "queued-failed", "queued-malformed", "queued-read-only":
				operation := "bootstrap"
				if state == "queued-read-only" {
					operation = "inspect-bootstrap"
				}
				raw := []byte(`{"inventory":{"all":{}},"variables":{}}`)
				if err := prepareLocalOperation(job, operation, raw, executionHash(raw), func(bundle string) error { return os.Mkdir(bundle, 0700) }); err != nil {
					t.Fatal(err)
				}
				receipt := []byte(`{"state":"failed"}`)
				if state == "queued-malformed" {
					receipt = []byte("{")
				}
				if err := writePrivate(filepath.Join(job, "receipt.json"), receipt); err != nil {
					t.Fatal(err)
				}
			}
			before := preflightSnapshot(t, root)
			err := PreflightLocalExecution()
			blocked := state == "present" || state == "malformed" || strings.HasPrefix(state, "queued-") && state != "queued-read-only"
			if blocked && !errors.Is(err, ErrExecutionFenced) || !blocked && err != nil {
				t.Fatalf("preflight %s: %v", state, err)
			}
			if after := preflightSnapshot(t, root); !reflect.DeepEqual(before, after) {
				t.Fatalf("preflight changed evidence: before=%v after=%v", before, after)
			}
		})
	}
}
func TestPreflightAbsentNamespaceIsNotCreated(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	if err := preflightExecutionAdmission(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("preflight created namespace", err)
	}
}
