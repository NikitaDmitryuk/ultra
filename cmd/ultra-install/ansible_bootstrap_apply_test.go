package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func bootstrapFailureFixture(t *testing.T, failRollback bool) (string, error) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "attempt")
	if err = os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"adoption-maintenance.json": `{"legacy":true}`, "inventory.frozen.json": `{"all":{}}`, "adoption-schedules.json": `["ultra-recovery-backup.timer"]`} {
		if err = os.WriteFile(filepath.Join(directory, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	stub := filepath.Join(root, "ansible-playbook")
	source := "#!" + python + `
import json,pathlib,sys
variables=json.loads((pathlib.Path(sys.argv[-1][1:]).parent/'variables.json').read_text())
job=pathlib.Path(variables['ultra_result_file']).parent
operation=json.loads((job/'job.json').read_text())['operation']
log=job.parent.parent/'operations'
with log.open('a') as stream:stream.write(operation+':'+str(variables.get('ultra_lifecycle_phase',''))+'\n')
if operation=='bootstrap':sys.exit(1)
result=pathlib.Path(variables['ultra_result_file']);result.write_text(json.dumps({'verified':True}));result.chmod(0o600)
`
	if failRollback {
		source = strings.Replace(
			source,
			"if operation=='bootstrap':sys.exit(1)",
			"if operation in ('bootstrap','rollback-adoption'):sys.exit(1)",
			1,
		)
	}
	if err = os.WriteFile(stub, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := deployansible.WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	p := &installplan.InstallPlan{Bridge: installplan.BridgeConfig{SSHHost: "192.0.2.1"}}
	inventory := map[string]any{"all": map[string]any{}}
	err = applyReservedBootstrap(ctx, context.Background(), p, inventory, nil, directory, root, root, python, stub, "human", release)
	if err == nil {
		t.Fatal("failed activation reported success")
	}
	raw, readErr := os.ReadFile(filepath.Join(root, "operations"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	return string(raw), err
}

func TestBootstrapMutationFailureRunsCompatibleRollbackBeforeRelease(t *testing.T) {
	operations, err := bootstrapFailureFixture(t, false)
	expected := "bootstrap:\nlifecycle:applying\nrollback-adoption:\nresume-schedules:\nlifecycle:released\n"
	if operations != expected {
		t.Fatalf("wrong failure recovery order: %q", operations)
	}
	if strings.Contains(err.Error(), "rollback_unconfirmed") {
		t.Fatal("verified rollback incorrectly reported unconfirmed", err)
	}
}
func TestBootstrapFailedCompatibleRollbackDoesNotResumeOrRelease(t *testing.T) {
	operations, err := bootstrapFailureFixture(t, true)
	if operations != "bootstrap:\nlifecycle:applying\nrollback-adoption:\n" {
		t.Fatalf("failed recovery reopened topology or schedules: %q", operations)
	}
	if !strings.Contains(err.Error(), "bootstrap_compatible_rollback_unconfirmed") {
		t.Fatal("unverified rollback lost failure reason", err)
	}
}
