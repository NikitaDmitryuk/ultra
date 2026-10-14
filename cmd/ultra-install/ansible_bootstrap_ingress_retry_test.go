package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestBootstrapIngressRetryDoesNotEnableOrdinaryIngressRetry(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := deployansible.WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	executable := filepath.Join(root, "ansible")
	source := "#!" + python + "\n" + `import pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
count=job/'calls'
n=int(count.read_text())+1 if count.exists() else 1
count.write_text(str(n))
if n==1:sys.exit(1)
result=job/'result.json'
result.write_text('{"verified":true}')
result.chmod(0o600)
`
	if err = os.WriteFile(executable, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	p := &installplan.InstallPlan{Automation: &installplan.AutomationConfig{Ingress: &installplan.AutomationIngress{Domain: "example.com"}}}
	inventory := map[string]any{}
	vars := map[string]any{"ultra_lock_directory": root}
	directory := filepath.Join(root, "ingress-prepare")
	if err = ansibleBootstrapIngress(ctx, p, inventory, directory, python, executable, "prepare", vars); err == nil {
		t.Fatal("initial failure missing")
	}
	if err = ansibleIngress(ctx, p, inventory, directory, python, executable, "prepare", vars); err == nil {
		t.Fatal("ordinary ingress retried failure")
	}
	if err = ansibleBootstrapIngress(ctx, p, inventory, directory, python, executable, "prepare", vars); err != nil {
		t.Fatal(err)
	}
	if err = ansibleBootstrapIngress(ctx, p, inventory, directory, python, executable, "prepare", vars); err != nil {
		t.Fatal(err)
	}
	calls, _ := os.ReadFile(filepath.Join(directory, "calls"))
	if string(calls) != "2" {
		t.Fatalf("unexpected executions: %s", calls)
	}
	if _, err = os.Stat(filepath.Join(directory, "history", "attempt-1.json")); err != nil {
		t.Fatal(err)
	}
	if err = ansibleBootstrapIngress(ctx, p, inventory, directory, python, executable, "rollback", vars); err == nil {
		t.Fatal("non-bootstrap action accepted")
	}
}
