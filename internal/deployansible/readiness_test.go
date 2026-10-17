package deployansible

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	if err := WaitUpgradeReadiness(context.Background(), map[string]any{}, root, python, runner, "11111111-2222-3333-4444-555555555555", false); err != nil {
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
	if err := WaitUpgradeReadiness(context.Background(), map[string]any{}, root, python, runner, "11111111-2222-3333-4444-555555555555", false); err != nil {
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
	if err := WaitUpgradeReadiness(ctx, nil, root, "/usr/bin/python3", "/usr/bin/true", "11111111-2222-3333-4444-555555555555", false); err == nil ||
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
			err := WaitUpgradeReadiness(context.Background(), map[string]any{}, root, python, runner, id, item.pending)
			if (err != nil) != item.wantError {
				t.Fatalf("error=%v wantError=%t", err, item.wantError)
			}
		})
	}
}
