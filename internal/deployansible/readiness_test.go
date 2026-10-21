package deployansible

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestReadinessProbeDoesNotAcquireSharedInfrastructureLock(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	runner := filepath.Join(root, "ansible")
	script := "#!" + python + "\n" + `import fcntl,json,os,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
request=json.loads((job/'request.json').read_text())
assert json.loads((job/'job.json').read_text())['operation']=='wait-upgrade-readiness'
root=pathlib.Path(request['variables']['ultra_lock_directory'])
fd=os.open(root/'infrastructure.lock',os.O_RDWR|os.O_CREAT,0o600)
try:
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    assert not (root/'reconcile-active').exists(), 'reconcile lock unexpectedly available'
except BlockingIOError:
    assert (root/'reconcile-active').exists(), 'probe acquired shared lock'
os.close(fd)
output=job/'result.json'
output.write_text(json.dumps({'verified':True,'ready':True}))
output.chmod(0o600)
`
	if err := os.WriteFile(runner, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	// With no reconcile, the probe must leave the lock available to a producer.
	if err := WaitUpgradeReadiness(context.Background(), map[string]any{}, root, python, runner, "11111111-2222-3333-4444-555555555555", false, ""); err != nil {
		t.Fatal(err)
	}
	// A running reconcile may hold the same lock throughout the probe.
	lock, err := controllerLock(filepath.Join(root, "infrastructure.lock"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := lock.Close(); err != nil {
			t.Errorf("close infrastructure lock: %v", err)
		}
	})
	if err := os.WriteFile(filepath.Join(root, "reconcile-active"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := WaitUpgradeReadiness(context.Background(), map[string]any{}, root, python, runner, "11111111-2222-3333-4444-555555555555", false, ""); err != nil {
		t.Fatal(err)
	}
	// Ordinary operations still require that lock, even for a readiness playbook.
	_, err = RunLocal(
		context.Background(),
		"inspect-upgrade",
		map[string]any{},
		map[string]any{"ultra_lock_directory": root},
		filepath.Join(root, "strict"),
		python,
		runner,
	)
	if err == nil {
		t.Fatal("strict inspection escaped shared lock")
	}
}

func TestReadinessProbeCancellationBeforeAttempt(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := WaitUpgradeReadiness(ctx, nil, root, "/usr/bin/python3", "/usr/bin/true",
		"11111111-2222-3333-4444-555555555555", false, "")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
}

func TestReadinessProbeCancellationDuringAttemptStopsRetries(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	runner := filepath.Join(root, "slow")
	started := filepath.Join(root, "started")
	calls := filepath.Join(root, "calls")
	script := "#!" + python + "\n" + `import pathlib,sys,time
root=pathlib.Path(__file__).parent
calls=root/'calls'
calls.write_text(str(int(calls.read_text())+1) if calls.exists() else '1')
(root/'started').write_text('started')
time.sleep(30)
`
	if err := os.WriteFile(runner, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		result <- WaitUpgradeReadiness(ctx, map[string]any{}, root, python, runner,
			"11111111-2222-3333-4444-555555555555", false, "")
	}()
	deadline := time.NewTimer(5 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer deadline.Stop()
	defer ticker.Stop()
	for {
		if _, err := os.Stat(started); err == nil {
			break
		}
		select {
		case err := <-result:
			t.Fatalf("readiness probe returned before runner started: %v", err)
		case <-deadline.C:
			t.Fatal("timed out waiting for runner start marker")
		case <-ticker.C:
		}
	}
	cancel()
	err = <-result
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v", err)
	}
	if got, readErr := os.ReadFile(calls); readErr != nil || string(got) != "1" {
		t.Fatalf("runner invocation count=%q, error=%v", got, readErr)
	}
}

func TestReadinessProbeRetriesTransientFailuresWithFreshStages(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	for _, tc := range []struct {
		name                string
		failures, wantCalls int
		code                string
	}{
		{name: "transient then success", failures: 1, wantCalls: 2, code: "ssh_banner_timeout"},
		{name: "exhaustion", failures: 3, wantCalls: 3, code: "ssh_connection_reset"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			operation := filepath.Join(root, "operation")
			if err := os.Mkdir(operation, 0700); err != nil {
				t.Fatal(err)
			}
			runner := filepath.Join(root, "runner")
			program := "#!" + python + "\n" + `import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
request=json.loads((job/'request.json').read_text())
root=pathlib.Path(request['variables']['ultra_lock_directory'])
count=root/'calls'
n=int(count.read_text())+1 if count.exists() else 1
count.write_text(str(n))
with (root/'stages').open('a') as f: f.write(str(job)+'\n')
if n <= ` + strconv.Itoa(tc.failures) + `:
 (job/'diagnostic.json').write_text(json.dumps({'stage':'Read readiness','node':'bridge','code':'` + tc.code + `'}))
 (job/'diagnostic.json').chmod(0o600)
 sys.exit(2)
out=job/'result.json'; out.write_text(json.dumps({'verified':True,'ready':True})); out.chmod(0o600)
`
			if err := os.WriteFile(runner, []byte(program), 0700); err != nil {
				t.Fatal(err)
			}
			err := WaitUpgradeReadiness(context.Background(), map[string]any{}, root, python, runner,
				"11111111-2222-3333-4444-555555555555", false, operation)
			if (err == nil) != (tc.wantCalls == 2) {
				t.Fatalf("error=%v", err)
			}
			count, _ := os.ReadFile(filepath.Join(root, "calls"))
			if string(count) != strconv.Itoa(tc.wantCalls) {
				t.Fatalf("calls=%q", count)
			}
			stages, _ := os.ReadFile(filepath.Join(root, "stages"))
			lines := strings.Split(strings.TrimSpace(string(stages)), "\n")
			if len(lines) != tc.wantCalls {
				t.Fatalf("stages=%q", stages)
			}
			seen := map[string]bool{}
			for _, path := range lines {
				if seen[path] {
					t.Fatalf("stage reused: %s", path)
				}
				seen[path] = true
			}
			files, _ := filepath.Glob(filepath.Join(operation, "readiness-diagnostic-*.json"))
			if len(files) != tc.failures {
				t.Fatalf("diagnostics=%v", files)
			}
		})
	}
}

func TestReadinessProbePersistsOnlySafeFailureDiagnostic(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	operation := filepath.Join(root, "upgrade")
	if err := os.Mkdir(operation, 0700); err != nil {
		t.Fatal(err)
	}
	runner := filepath.Join(root, "ansible-fail")
	script := "#!" + python + "\n" + `import json,os,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
(job/'diagnostic.json').write_text(json.dumps({'stage':'Inspect current broker readiness','node':'bridge','code':'task_failed'}))
(job/'diagnostic.json').chmod(0o600)
sys.exit(2)
`
	if err := os.WriteFile(runner, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	err = WaitUpgradeReadiness(context.Background(), map[string]any{}, root, python, runner,
		"11111111-2222-3333-4444-555555555555", false, operation)
	if err == nil {
		t.Fatal("failed readiness probe succeeded")
	}
	paths, err := filepath.Glob(filepath.Join(operation, "readiness-diagnostic-*.json"))
	if err != nil || len(paths) != 1 {
		t.Fatalf("diagnostic files=%v err=%v", paths, err)
	}
	info, err := os.Stat(paths[0])
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private diagnostic stat=%v err=%v", info, err)
	}
	var diagnostic Diagnostic
	raw, err := os.ReadFile(paths[0])
	if err != nil || json.Unmarshal(raw, &diagnostic) != nil {
		t.Fatalf("read diagnostic: %v", err)
	}
	if diagnostic != (Diagnostic{Stage: "Inspect current broker readiness", Node: "bridge", Code: "task_failed"}) {
		t.Fatalf("unexpected diagnostic: %+v", diagnostic)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil || len(fields) != 3 {
		t.Fatalf("diagnostic contains unexpected fields: %s (%v)", raw, err)
	}
	if err := os.WriteFile(runner, []byte("#!"+python+"\n"+`import json,os,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
(job/'diagnostic.json').write_text(json.dumps({'stage':'Inspect second readiness attempt','node':'bridge','code':'task_failed'}))
(job/'diagnostic.json').chmod(0o600)
sys.exit(2)
`), 0700); err != nil {
		t.Fatal(err)
	}
	_ = WaitUpgradeReadiness(context.Background(), map[string]any{}, root, python, runner,
		"11111111-2222-3333-4444-555555555555", false, operation)
	paths, err = filepath.Glob(filepath.Join(operation, "readiness-diagnostic-*.json"))
	if err != nil || len(paths) != 2 {
		t.Fatalf("retry diagnostic files=%v err=%v", paths, err)
	}
	latest, err := os.ReadFile(paths[1])
	if err != nil || json.Unmarshal(latest, &diagnostic) != nil || diagnostic.Stage != "Inspect second readiness attempt" {
		t.Fatalf("latest diagnostic=%s err=%v", latest, err)
	}
}

func TestReadinessProbeRejectsLeasedContextAndGenericEntryPoint(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := WaitUpgradeReadiness(ctx, nil, root, "/usr/bin/python3", "/usr/bin/true", "11111111-2222-3333-4444-555555555555", false, ""); err == nil ||
		!strings.Contains(err.Error(), "unleased_context") {
		t.Fatalf("leased probe accepted: %v", err)
	}
	_, err = RunLocal(
		context.Background(),
		"wait-upgrade-readiness",
		nil,
		map[string]any{"ultra_lock_directory": root},
		filepath.Join(root, "probe"),
		"/usr/bin/python3",
		"/usr/bin/true",
	)
	if err == nil || !strings.Contains(err.Error(), "requires_dedicated_entrypoint") {
		t.Fatalf("generic probe accepted: %v", err)
	}
}

func TestReadinessProbeRequiresCurrentExactReservationForPendingJob(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	const id = "11111111-2222-3333-4444-555555555555"
	for _, item := range []struct {
		name, result       string
		pending, wantError bool
	}{
		{"ready", `{"verified":true,"ready":true}`, false, false},
		{"pending-ready", `{"verified":true,"ready":true}`, true, true},
		{"pending-same", `{"verified":true,"reservation_id":"11111111-2222-3333-4444-555555555555","reservation_phase":"applying"}`, true, false},
		{"foreign", `{"verified":true,"reservation_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa","reservation_phase":"applying"}`, true, true},
		{"checking", `{"verified":true,"reservation_id":"11111111-2222-3333-4444-555555555555","reservation_phase":"checking"}`, true, true},
		{"unverified", `{"ready":true}`, false, true},
	} {
		t.Run(item.name, func(t *testing.T) {
			runner := filepath.Join(root, "ansible-"+item.name)
			script := "#!" + python + "\nimport pathlib,sys\njob=pathlib.Path(sys.argv[-1][1:]).parent\noutput=job/'result.json'\noutput.write_text('" + item.result + "')\noutput.chmod(0o600)\n"
			if err := os.WriteFile(runner, []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			err := WaitUpgradeReadiness(context.Background(), map[string]any{}, root, python, runner, id, item.pending, "")
			if (err != nil) != item.wantError {
				t.Fatalf("error=%v wantError=%t", err, item.wantError)
			}
		})
	}
}
