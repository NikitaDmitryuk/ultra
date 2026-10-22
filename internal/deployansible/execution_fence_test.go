package deployansible

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func executionFixture(t *testing.T) (string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	old := executionFenceDirectory
	executionFenceDirectory = func(string) string { return root }
	t.Cleanup(func() { executionFenceDirectory = old })
	return root, filepath.Join(root, "job-one")
}
func prepareExecutionFixture(t *testing.T, directory string) {
	t.Helper()
	raw := []byte(`{"inventory":{"all":{}},"variables":{}}`)
	if err := prepareLocalOperation(directory, "bootstrap", raw, executionHash(raw), func(bundle string) error {
		if err := os.Mkdir(bundle, 0700); err != nil {
			return err
		}
		return writePrivate(filepath.Join(bundle, "controller.py"), []byte("# frozen controller\n"))
	}); err != nil {
		t.Fatal(err)
	}
}
func TestExecutionFenceBlocksSameAndDifferentJob(t *testing.T) {
	root, job := executionFixture(t)
	prepareExecutionFixture(t, job)
	first, err := beginExecution(job)
	if err != nil || first == nil {
		t.Fatal(first, err)
	}
	for _, next := range []string{job, filepath.Join(root, "job-two")} {
		if next != job {
			prepareExecutionFixture(t, next)
		}
		if _, err = beginExecution(next); !errors.Is(err, ErrExecutionFenced) {
			t.Fatalf("redispatch admitted %s: %v", next, err)
		}
	}
	// Failed receipt and free local locks never close the fence.
	if err = writeJSON(filepath.Join(job, "receipt.json"), map[string]any{"state": "failed"}); err != nil {
		t.Fatal(err)
	}
	if err = ReconcileExecutionFence(*first); !errors.Is(err, ErrExecutionFenced) {
		t.Fatal(err)
	}
	current, err := InspectExecutionFence()
	if err != nil || current == nil || *current != *first {
		t.Fatal(current, err)
	}
}
func TestExecutionFenceReconcileExactNormalCompletion(t *testing.T) {
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
	// Success by itself cannot clear uncertainty.
	if err = ReconcileExecutionFence(*fence); !errors.Is(err, ErrExecutionFenced) {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(job, "receipt.json"))
	complete := map[string]any{"fence": fence, "local_cleanup": true, "receipt_sha256": executionHash(raw)}
	if err = writeJSON(filepath.Join(job, "execution-completion.json"), complete); err != nil {
		t.Fatal(err)
	}
	wrong := *fence
	wrong.Generation = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err = ReconcileExecutionFence(wrong); !errors.Is(err, ErrExecutionFenced) {
		t.Fatal(err)
	}
	if err = ReconcileExecutionFence(*fence); err != nil {
		t.Fatal(err)
	}
	current, err := InspectExecutionFence()
	if err != nil || current != nil {
		t.Fatal(current, err)
	}
}
func TestExecutionFenceLegacyRunningAndReadOnly(t *testing.T) {
	_, job := executionFixture(t)
	prepareExecutionFixture(t, job)
	if err := writeJSON(filepath.Join(job, "receipt.json"), map[string]any{"state": "running"}); err != nil {
		t.Fatal(err)
	}
	if _, err := beginExecution(job); !errors.Is(err, ErrExecutionFenced) {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(job, "job.json"))
	var seal map[string]any
	if json.Unmarshal(raw, &seal) != nil {
		t.Fatal("seal")
	}
	seal["operation"] = "inspect-bootstrap"
	updated, _ := json.Marshal(seal)
	if err := os.WriteFile(filepath.Join(job, "job.json"), updated, 0600); err != nil {
		t.Fatal(err)
	}
	if fence, err := beginExecution(job); err != nil || fence != nil {
		t.Fatal(fence, err)
	}
}

func TestExecutionFenceGoControllerHandoff(t *testing.T) {
	root, job := executionFixture(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	raw := []byte(`{"inventory":{"all":{}},"variables":{}}`)
	if err = prepareLocalOperation(job, "bootstrap", raw, executionHash(raw), Export); err != nil {
		t.Fatal(err)
	}
	// Internal test injection only: rewrite the exported private fixture before
	// computing the execution binding. Production has no root override.
	controller := filepath.Join(job, "bundle", "controller.py")
	source, err := os.ReadFile(controller)
	if err != nil {
		t.Fatal(err)
	}
	source = []byte(
		strings.Replace(
			string(source),
			"EXECUTION_ROOT = Path('/var/lib/ultra-ansible')",
			"EXECUTION_ROOT = Path("+strconvQuote(root)+")",
			1,
		),
	)
	if err = os.WriteFile(controller, source, 0600); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(root, "ansible-playbook")
	script := "#!" + python + "\nimport json,pathlib,sys\nv=json.loads((pathlib.Path(sys.argv[-1][1:]).parent/'variables.json').read_text())\np=pathlib.Path(v['ultra_result_file']);p.write_text('{\"verified\":true}');p.chmod(0o600)\n"
	if err = os.WriteFile(stub, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	receipt, err := RunLocal(
		context.Background(),
		"bootstrap",
		map[string]any{"all": map[string]any{}},
		map[string]any{},
		job,
		python,
		stub,
	)
	if err != nil || receipt.State != "succeeded" {
		t.Fatal(receipt, err)
	}
	fence, err := InspectExecutionFence()
	if err != nil || fence != nil {
		t.Fatal(fence, err)
	}
	if err = os.Remove(filepath.Join(job, "receipt.json")); err != nil {
		t.Fatal(err)
	}
	if _, err = RunLocal(context.Background(), "bootstrap", map[string]any{"all": map[string]any{}}, map[string]any{}, job, python, stub); !errors.Is(
		err,
		ErrExecutionFenced,
	) {
		t.Fatal("lost receipt admitted same attempt", err)
	}
}

func strconvQuote(value string) string { raw, _ := json.Marshal(value); return string(raw) }

func TestExecutionFenceAdoptsLegacyBeforeQueueAdmission(t *testing.T) {
	root, old := executionFixture(t)
	prepareExecutionFixture(t, old)
	if err := writeJSON(filepath.Join(old, "receipt.json"), map[string]any{"state": "running", "code": "interrupted"}); err != nil {
		t.Fatal(err)
	}
	if err := executionAdmission(filepath.Join(root, "different-job")); !errors.Is(err, ErrExecutionFenced) {
		t.Fatal(err)
	}
	fence, err := InspectExecutionFence()
	if err != nil || fence == nil || fence.JobDirectory != old {
		t.Fatal(fence, err)
	}
}

func TestExecutionFencePythonRegression(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	script, err := filepath.Abs("../../scripts/test-ansible-controller-fence.py")
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(python, script).CombinedOutput()
	if err != nil {
		t.Fatalf("Python fence regression: %v\n%s", err, output)
	}
}

func TestExecutionFenceRealAnsibleTaskFailureRetry(t *testing.T) {
	root, job := executionFixture(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	configuredAnsible := os.Getenv("ULTRA_TEST_ANSIBLE_PLAYBOOK")
	if configuredAnsible == "" {
		t.Skip("set ULTRA_TEST_ANSIBLE_PLAYBOOK to run the pinned Ansible integration test")
	}
	ansible, err := exec.LookPath(configuredAnsible)
	if err != nil {
		t.Skip("configured Ansible unavailable")
	}
	marker := filepath.Join(root, "allow-success")
	variables := map[string]any{"ultra_lock_directory": root, "fixture_toggle": marker}
	inventory := map[string]any{}
	raw, _ := json.Marshal(map[string]any{"inventory": inventory, "variables": variables})
	if err = prepareLocalOperation(job, "bootstrap", raw, executionHash(raw), Export); err != nil {
		t.Fatal(err)
	}
	controller := filepath.Join(job, "bundle", "controller.py")
	source, err := os.ReadFile(controller)
	if err != nil {
		t.Fatal(err)
	}
	source = []byte(
		strings.Replace(
			string(source),
			"EXECUTION_ROOT = Path('/var/lib/ultra-ansible')",
			"EXECUTION_ROOT = Path("+strconvQuote(root)+")",
			1,
		),
	)
	if err = os.WriteFile(controller, source, 0600); err != nil {
		t.Fatal(err)
	}
	playbook := `---
- hosts: localhost
  gather_facts: false
  tasks:
    - name: Inspect fixture gate
      ansible.builtin.stat:
        path: "{{ fixture_toggle }}"
      register: fixture_gate
    - name: Fail as a completed local task before operator retry
      ansible.builtin.fail:
        msg: fixture failure
      when: not fixture_gate.stat.exists
    - name: Acknowledge fixture success
      ansible.builtin.copy:
        dest: "{{ ultra_result_file }}"
        content: '{"verified":true}'
        mode: '0600'
`
	if err = os.WriteFile(filepath.Join(job, "bundle", "playbooks", "bootstrap.yml"), []byte(playbook), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	first, err := RunLocal(ctx, "bootstrap", inventory, variables, job, python, ansible)
	if err == nil || first.State != "failed" {
		t.Fatalf("expected completed task failure: %+v %v", first, err)
	}
	fence, err := InspectExecutionFence()
	if err != nil || fence != nil {
		for _, name := range []string{"receipt.json", "execution-completion.json", "diagnostic.json"} {
			data, _ := os.ReadFile(filepath.Join(job, name))
			t.Log(name, string(data))
		}
		names, _ := filepath.Glob(filepath.Join(job, "execution-terminal-*.json"))
		for _, name := range names {
			data, _ := os.ReadFile(name)
			t.Log("terminal", string(data))
		}
		t.Fatalf("normal failure did not release exact completion: %+v %v", fence, err)
	}
	if !completedExecution(job) {
		t.Fatal("missing exact failed-terminal completion")
	}
	beforeReplay, _ := os.ReadFile(filepath.Join(job, "receipt.json"))
	if _, err = RunLocal(ctx, "bootstrap", inventory, variables, job, python, ansible); err == nil {
		t.Fatal("cached failed task reported success")
	}
	afterReplay, _ := os.ReadFile(filepath.Join(job, "receipt.json"))
	if string(beforeReplay) != string(afterReplay) {
		t.Fatal("ordinary failed replay dispatched")
	}
	if fence, err = InspectExecutionFence(); err != nil || fence != nil {
		t.Fatalf("cached failure stranded a new fence: %+v %v", fence, err)
	}
	if err = os.WriteFile(marker, []byte("operator retry"), 0600); err != nil {
		t.Fatal(err)
	}
	// Inject the real public API's crash boundary AFTER job.json advanced but
	// BEFORE removal of the old failed receipt. No new executor may run yet.
	originalSync := syncLocalRetryDirectory
	calls := 0
	syncLocalRetryDirectory = func(path string) error {
		calls++
		if calls == 3 {
			return syscall.ENOSPC
		}
		return originalSync(path)
	}
	_, crashErr := RunLocalRetryFailed(ctx, "bootstrap", inventory, variables, job, python, ansible)
	syncLocalRetryDirectory = originalSync
	if !errors.Is(crashErr, syscall.ENOSPC) {
		t.Fatalf("missing job-rename fault: %v", crashErr)
	}
	if completedExecution(job) || !preparedRetryExecution(job) {
		t.Fatal("retry metadata crash not exactly authenticated")
	}
	if fence, e := InspectExecutionFence(); e != nil || fence != nil {
		t.Fatalf("metadata-only crash adopted uncertain execution: %+v %v", fence, e)
	}
	receipt, err := RunLocalRetryFailed(ctx, "bootstrap", inventory, variables, job, python, ansible)
	if err != nil || receipt.State != "succeeded" {
		t.Fatalf("explicit retry failed: %+v %v", receipt, err)
	}
	currentRaw, _ := os.ReadFile(filepath.Join(job, "job.json"))
	var current map[string]any
	_ = json.Unmarshal(currentRaw, &current)
	if current["attempt"] != float64(2) {
		t.Fatalf("retry dispatched more than one new attempt: %s", currentRaw)
	}
	if _, e := RunLocalRetryFailed(ctx, "bootstrap", inventory, variables, job, python, ansible); e != nil {
		t.Fatal(e)
	}
	again, _ := os.ReadFile(filepath.Join(job, "job.json"))
	if string(again) != string(currentRaw) {
		t.Fatal("successful replay advanced another attempt")
	}
}
