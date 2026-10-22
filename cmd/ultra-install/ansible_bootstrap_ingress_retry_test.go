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
	if err = os.WriteFile(executable, withNormalAnsibleFailure(source), 0700); err != nil {
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

func TestBootstrapIngressRetryPreservesAnchorTransaction(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	for _, action := range []string{"prepare", "activate"} {
		t.Run(action, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
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
if job.name.startswith('ingress-') and n==1:sys.exit(1)
result=job/'result.json'
result.write_text('{"verified":true}')
result.chmod(0o600)
`
			if err := os.WriteFile(executable, withNormalAnsibleFailure(source), 0700); err != nil {
				t.Fatal(err)
			}
			p := &installplan.InstallPlan{Automation: &installplan.AutomationConfig{
				Ingress: &installplan.AutomationIngress{Domain: "example.com"},
			}}
			inventory := map[string]any{}
			vars := map[string]any{"ultra_lock_directory": root}
			anchor := filepath.Join(root, "bootstrap-postgres")
			if _, err := deployansible.RunLocal(ctx, "bootstrap-postgres", inventory, vars, anchor, python, executable); err != nil {
				t.Fatal(err)
			}
			stage := "ingress-" + action
			directory := filepath.Join(root, stage)
			original := bootstrapMutationOriginalStage(root, stage, 1)
			if original != anchor {
				t.Fatalf("initial source = %q, want anchor", original)
			}
			if err := ansibleBootstrapIngress(ctx, p, inventory, directory, python, executable, action, vars, original); err == nil {
				t.Fatal("initial failure missing")
			}
			before, err := os.ReadFile(filepath.Join(directory, "request.json"))
			if err != nil {
				t.Fatal(err)
			}
			original = bootstrapMutationOriginalStage(root, stage, 1)
			if original != "" {
				t.Fatalf("retry source = %q, want existing stage", original)
			}
			p.Automation.Ingress.Domain = "changed.example.com"
			if err := ansibleBootstrapIngress(ctx, p, inventory, directory, python, executable, action, vars, original); err == nil {
				t.Fatal("changed ingress input accepted")
			}
			p.Automation.Ingress.Domain = "example.com"
			if err := ansibleBootstrapIngress(ctx, p, inventory, directory, python, executable, action, vars, original); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(filepath.Join(directory, "request.json"))
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatal("frozen ingress request changed")
			}
			calls, err := os.ReadFile(filepath.Join(directory, "calls"))
			if err != nil || string(calls) != "2" {
				t.Fatalf("unexpected executions: %s, error: %v", calls, err)
			}
		})
	}
}
