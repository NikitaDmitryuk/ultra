package deployansible

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLocalOperationFreezesInputsAndRequiresReceipt(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "ansible")
	source := "#!" + python + "\n" + `import json,pathlib,sys
variables=json.loads((pathlib.Path(sys.argv[-1][1:]).parent/'variables.json').read_text())
result=pathlib.Path(variables['ultra_result_file'])
result.write_text(json.dumps({'verified': True}))
result.chmod(0o600)
count=result.parent/'calls'
count.write_text(str(int(count.read_text())+1 if count.exists() else 1))
`
	if err = os.WriteFile(executable, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	inventory := map[string]any{"all": map[string]any{"hosts": map[string]any{"test": map[string]any{"ansible_connection": "local"}}}}
	vars := map[string]any{"ultra_postgres_password": "fixture-password", "literal": "{{ lookup('pipe', 'false') }}"}
	directory := filepath.Join(root, "attempt")
	for i := 0; i < 2; i++ {
		receipt, err := RunLocal(context.Background(), "inspect-bootstrap", inventory, vars, directory, python, executable)
		if err != nil || receipt.Result.Values["verified"] != true {
			t.Fatalf("run %d: %v %v", i, err, receipt)
		}
	}
	calls, _ := os.ReadFile(filepath.Join(directory, "calls"))
	if string(calls) != "1" {
		t.Fatal("replayed completed operation")
	}
	for _, member := range []string{"request.json", "job.json", "receipt.json"} {
		info, statErr := os.Stat(filepath.Join(directory, member))
		if statErr != nil || info.Mode().Perm()&0077 != 0 {
			t.Fatalf("secret-bearing operation member %s is not private: %v", member, statErr)
		}
	}
	for _, key := range []string{"literal", "ultra_postgres_password"} {
		original := vars[key]
		vars[key] = "changed-fixture-value"
		if _, err = RunLocal(context.Background(), "inspect-bootstrap", inventory, vars, directory, python, executable); err == nil {
			t.Fatalf("changed %s inputs reused", key)
		}
		vars[key] = original
	}
	if _, err = RunLocal(context.Background(), "arbitrary", inventory, vars, filepath.Join(root, "invalid"), python, executable); err == nil {
		t.Fatal("unapproved operation")
	}
	for _, operation := range []string{"verify", "configure-exit", "configure-replica", "stop-replica"} {
		if _, err = RunLocal(context.Background(), operation, inventory, vars, filepath.Join(root, operation), python, executable); err == nil {
			t.Fatalf("removed or typed worker operation %q accepted by local adapter", operation)
		}
	}
	if _, err = RunLocal(context.Background(), "inspect-bootstrap", inventory, vars, filepath.Join(root, "failed"), python, "/bin/true"); err == nil {
		t.Fatal("missing receipt accepted")
	}
}

func TestOperationLeaseCannotBeReusedAfterRelease(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = WithOperationLock(context.Background(), root); err == nil {
		release()
		t.Fatal("second mutator acquired same lease")
	}
	release()
	if _, err = RunLocal(ctx, "inspect-bootstrap", map[string]any{}, map[string]any{}, filepath.Join(root, "attempt"), "/usr/bin/python3", "/bin/true"); err == nil {
		t.Fatal("released lease allowed mutation")
	}
	_, nextRelease, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	nextRelease()
}
