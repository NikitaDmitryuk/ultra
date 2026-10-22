package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func undispatchedFixture(t *testing.T, bridge bool) (retainedPrimaryRebuildInput, []string) {
	t.Helper()
	in, paths := reconcileFixtureScoped(t, false, bridge)
	for _, name := range []string{"receipt.json", "result.json"} {
		if err := os.Remove(filepath.Join(in.Directory, "execute", name)); err != nil {
			t.Fatal(err)
		}
	}
	return in, paths
}

// Only a prepared attempt is abandonable, and its digests must be recorded.
func TestRetainedUndispatchedAcceptsPreparedWorkspace(t *testing.T) {
	in, p := undispatchedFixture(t, true)
	got, artifacts, err := verifyRetainedUndispatchedWorkspace(p[0], p[1], p[2], p[3])
	if err != nil {
		t.Fatal(err)
	}
	if got.FenceEvidenceSHA256 != in.FenceEvidenceSHA256 || got.Directory != p[0] {
		t.Fatal("abandoned binding or directory not preserved")
	}
	for _, name := range []string{"prepared", "request", "job", "bundle_receipt"} {
		if !rebuildSHA.MatchString(artifacts[name]) {
			t.Fatalf("artifact %q not digested: %v", name, artifacts)
		}
	}
}

// A dispatch claim or any executor output means the attempt may have mutated the
// fleet, so it must be reconciled rather than abandoned.
func TestRetainedUndispatchedRefusesDispatchEvidence(t *testing.T) {
	for _, name := range []string{
		"receipt.json",
		"result.json",
		"inventory.json",
		"variables.json",
		"execution-dispatch-1.json",
	} {
		t.Run(name, func(t *testing.T) {
			in, p := undispatchedFixture(t, true)
			path := filepath.Join(in.Directory, "execute", name)
			if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := verifyRetainedUndispatchedWorkspace(p[0], p[1], p[2], p[3]); err == nil ||
				err.Error() != "retained_abandon_workspace_dispatched" {
				t.Fatalf("dispatch evidence accepted: %v", err)
			}
		})
	}
}

// A two-host attempt claimed the retained exit with the same binding, so retiring
// the bridge marker alone would leave that exit fenced with no local record.
func TestRetainedUndispatchedRefusesSharedOrRetainedScope(t *testing.T) {
	_, shared := undispatchedFixture(t, false)
	if _, _, err := verifyRetainedUndispatchedWorkspace(shared[0], shared[1], shared[2], shared[3]); err == nil ||
		err.Error() != "retained_abandon_scope_not_bridge_only" {
		t.Fatalf("two-host attempt accepted: %v", err)
	}
	in, p := undispatchedFixture(t, true)
	in.RetainedExit.FenceSHA256 = in.FenceEvidenceSHA256
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(in.Directory, "prepared-input.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = verifyRetainedUndispatchedWorkspace(p[0], p[1], p[2], p[3]); err == nil ||
		err.Error() != "retained_abandon_scope_not_bridge_only" {
		t.Fatalf("retained exit binding accepted: %v", err)
	}
}

func TestRetainedUndispatchedRefusesChangedOriginals(t *testing.T) {
	for _, index := range []int{1, 2, 3} {
		t.Run(filepath.Base(indexed(t, index)), func(t *testing.T) {
			_, p := undispatchedFixture(t, true)
			if err := os.WriteFile(p[index], []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, err := verifyRetainedUndispatchedWorkspace(p[0], p[1], p[2], p[3]); err == nil ||
				err.Error() != "retained_abandon_original_changed" {
				t.Fatalf("changed original accepted: %v", err)
			}
		})
	}
}

func indexed(t *testing.T, index int) string {
	t.Helper()
	return []string{"directory", "config", "manifest", "journal"}[index]
}

func TestRetainedAbandonProgramCompiles(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	command := exec.Command("python3", "-c", "import sys; compile(sys.stdin.read(),'<abandon>','exec')")
	command.Stdin = strings.NewReader(retainedAbandonProgram)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
}

func abandonRemoteFixture(t *testing.T) (string, string, string, string) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	d := t.TempDir()
	state := filepath.Join(d, "state")
	system := filepath.Join(d, "systemd")
	proc := filepath.Join(d, "proc")
	for _, p := range []string{state, filepath.Join(state, "operator-inputs"), system, proc} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"infrastructure.lock", "operator-inputs/manual-deploy.lock"} {
		if err := os.WriteFile(filepath.Join(state, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	marker := `{"protocol":"retained-primary-admission-v1","binding_sha256":"fixture"}`
	if err := os.WriteFile(filepath.Join(state, "retained-primary-admission.json"), []byte(marker), 0600); err != nil {
		t.Fatal(err)
	}
	for _, unit := range []string{
		"ultra-ansible-controller.service",
		"ultra-recovery-reconcile.service",
		"ultra-recovery-reconcile.timer",
	} {
		dir := filepath.Join(system, unit+".d")
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "90-retained-primary.conf"), []byte(retainedFenceDropin), 0644); err != nil {
			t.Fatal(err)
		}
	}
	program := strings.Replace(
		retainedAbandonProgram,
		"state=Path('/var/lib/ultra-ansible')",
		"state=Path("+fmtPython(state)+")",
		1,
	)
	program = strings.Replace(program, "system=Path('/etc/systemd/system')", "system=Path("+fmtPython(system)+")", 1)
	program = strings.Replace(program, "Path('/proc')", "Path("+fmtPython(proc)+")", 1)
	program = strings.Replace(program, "for ancestor in [p]+list(p.parents):", "for ancestor in [p]:", 1)
	program = strings.Replace(program, "s.st_uid==0", "s.st_uid==os.geteuid()", 1)
	// Only systemd is mocked; ownership, locks, the second proof, the rename and
	// the drop-in removal all run the real program.
	mock := `import subprocess,types
def run(args,**kw):
 if len(args)>1 and args[1]=='show':
  return types.SimpleNamespace(returncode=0,stdout='LoadState=loaded\nActiveState=inactive\nRefuseManualStart=yes\n')
 return types.SimpleNamespace(returncode=0,stdout='')
subprocess.run=run
`
	return mock + program, state, system, proc
}

func runAbandonRemoteTest(t *testing.T, program, input string) ([]byte, error) {
	t.Helper()
	command := exec.Command("python3", "-u", "-c", program, "fixture")
	command.Stdin = strings.NewReader(input)
	return command.CombinedOutput()
}

func TestRetainedAbandonProgramRetiresMarkerAndFence(t *testing.T) {
	program, state, system, _ := abandonRemoteFixture(t)
	marker := `{"protocol":"retained-primary-admission-v1","binding_sha256":"fixture"}`
	out, err := runAbandonRemoteTest(t, program, "abandon\n")
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	digest := digestSHA256([]byte(marker))
	retired := filepath.Join(state, "retained-primary-admission.abandoned-"+digest+".json")
	if _, statErr := os.Lstat(filepath.Join(state, "retained-primary-admission.json")); !os.IsNotExist(statErr) {
		t.Fatal("admission marker was not renamed")
	}
	raw, readErr := os.ReadFile(retired)
	if readErr != nil || string(raw) != marker {
		t.Fatalf("abandoned evidence not preserved: %v", readErr)
	}
	if !bytes.Contains(out, []byte(`{"marker_sha256": "`+digest+`"}`)) {
		t.Fatalf("marker digest not proven: %s", out)
	}
	for _, unit := range []string{
		"ultra-ansible-controller.service",
		"ultra-recovery-reconcile.service",
		"ultra-recovery-reconcile.timer",
	} {
		if _, statErr := os.Lstat(filepath.Join(system, unit+".d", "90-retained-primary.conf")); !os.IsNotExist(statErr) {
			t.Fatalf("%s fence not released", unit)
		}
	}
	// A retired admission cannot be retired twice.
	if out, err = runAbandonRemoteTest(t, program, "abandon\n"); err == nil || bytes.Contains(out, []byte("abandoned\n")) {
		t.Fatalf("retired admission accepted: %s", out)
	}
}

// EOF alone is never an authorization: the operator must send the command.
func TestRetainedAbandonProgramRequiresExplicitCommand(t *testing.T) {
	program, state, system, _ := abandonRemoteFixture(t)
	out, err := runAbandonRemoteTest(t, program, "")
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if bytes.Contains(out, []byte("abandoned\n")) {
		t.Fatalf("EOF abandoned the admission: %s", out)
	}
	if _, statErr := os.Lstat(filepath.Join(state, "retained-primary-admission.json")); statErr != nil {
		t.Fatal("EOF removed the admission marker")
	}
	if _, statErr := os.Lstat(filepath.Join(system, "ultra-ansible-controller.service.d/90-retained-primary.conf")); statErr != nil {
		t.Fatal("EOF released the controller fence")
	}
}

func TestRetainedAbandonProgramRejectsUnsafeState(t *testing.T) {
	for _, kind := range []string{
		"wrong-binding",
		"opened",
		"recovery-fence",
		"recovery-anchor",
		"executor",
		"changed-dropin",
		"active-unit",
		"lock-busy",
	} {
		t.Run(kind, func(t *testing.T) {
			program, state, system, proc := abandonRemoteFixture(t)
			switch kind {
			case "wrong-binding":
				write := `{"protocol":"retained-primary-admission-v1","binding_sha256":"other"}`
				if err := os.WriteFile(filepath.Join(state, "retained-primary-admission.json"), []byte(write), 0600); err != nil {
					t.Fatal(err)
				}
			case "opened":
				_ = os.WriteFile(filepath.Join(state, "retained-primary-admission-open"), nil, 0600)
			case "recovery-fence":
				_ = os.WriteFile(filepath.Join(state, "recovery-fence.json"), []byte(`{}`), 0600)
			case "recovery-anchor":
				_ = os.WriteFile(filepath.Join(state, "recovery-anchor.json"), []byte(`{}`), 0600)
			case "executor":
				if err := os.Mkdir(filepath.Join(proc, "123"), 0700); err != nil {
					t.Fatal(err)
				}
				_ = os.WriteFile(filepath.Join(proc, "123", "cmdline"), []byte("python3\x00controller.py\x00"), 0600)
			case "changed-dropin":
				p := filepath.Join(system, "ultra-recovery-reconcile.service.d/90-retained-primary.conf")
				if err := os.WriteFile(p, []byte("[Unit]\nRefuseManualStart=no\n"), 0644); err != nil {
					t.Fatal(err)
				}
			case "active-unit":
				program = strings.Replace(program, "ActiveState=inactive", "ActiveState=active", 1)
			case "lock-busy":
				program = strings.Replace(
					program,
					"fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)",
					"(_ for _ in []).throw(BlockingIOError())",
					1,
				)
			}
			if out, err := runAbandonRemoteTest(t, program, "abandon\n"); err == nil ||
				bytes.Contains(out, []byte("abandoned\n")) {
				t.Fatalf("unsafe state abandoned: %s", out)
			}
			if _, statErr := os.Lstat(filepath.Join(state, "retained-primary-admission.json")); statErr != nil {
				t.Fatal("unsafe state lost the admission marker")
			}
		})
	}
}
