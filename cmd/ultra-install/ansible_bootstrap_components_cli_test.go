package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func TestResumeBootstrapComponentsUsesCurrentAdapterGeneration(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	if err = os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	attempt := filepath.Join(root, "attempt")
	if err = os.Mkdir(attempt, 0700); err != nil {
		t.Fatal(err)
	}
	inventory := map[string]any{"all": map[string]any{"children": map[string]any{
		"exits": map[string]any{"hosts": map[string]any{"exit_0": map[string]any{}}},
	}}}
	variables := map[string]any{"ultra_lock_directory": root}
	frozen, _ := json.Marshal(inventory)
	if err = os.WriteFile(filepath.Join(attempt, "inventory.frozen.json"), frozen, 0600); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(root, "ansible-playbook")
	script := "#!" + python + `
import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
operation=json.loads((job/'job.json').read_text())['operation']
v=json.loads((job/'variables.json').read_text())
if operation=='bootstrap':sys.exit(1)
r={'verified':True}
if operation=='bootstrap-exit':r.update(exit_host=v['ultra_bootstrap_exit_host'],cert_pin='a'*64)
f=job/'result.json';f.write_text(json.dumps(r));f.chmod(0o600)
`
	if err = os.WriteFile(stub, withNormalAnsibleFailure(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := deployansible.WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	stage := filepath.Join(attempt, "apply")
	if _, err = deployansible.RunLocalRetryFailed(ctx, "bootstrap", inventory, variables, stage, python, stub); err == nil {
		t.Fatal("legacy failure missing")
	}
	before, err := os.ReadFile(filepath.Join(stage, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Calculate the previous adapter generation exactly as the old CLI did.
	id := sha256.New()
	for _, name := range []string{"controller.py", "playbooks/bootstrap-postgres.yml", "playbooks/bootstrap-exit.yml", "playbooks/bootstrap-bridge.yml"} {
		data, readErr := ansibleassets.Bundle.ReadFile(name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		_, _ = id.Write([]byte(name + "\x00"))
		_, _ = id.Write(data)
	}
	old := filepath.Join(attempt, "linked-components-"+hex.EncodeToString(id.Sum(nil))[:16])
	if err = os.Mkdir(old, 0700); err != nil {
		t.Fatal(err)
	}
	oldProof := []byte(`{"adapter_sha256":"previous-generation"}`)
	if err = os.WriteFile(filepath.Join(old, "bundle.adapter.json"), oldProof, 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"roles/db_tunnel/tasks/reuse.yml", "roles/db_tunnel/tasks/install.yml"} {
		data, readErr := ansibleassets.Bundle.ReadFile(name)
		if readErr != nil {
			t.Fatal(readErr)
		}
		_, _ = id.Write([]byte(name + "\x00"))
		_, _ = id.Write(data)
	}
	expected := filepath.Join(attempt, "linked-components-"+hex.EncodeToString(id.Sum(nil))[:16])
	for n := 0; n < 2; n++ {
		if _, err = resumeBootstrapComponents(ctx, stage, python, stub); err != nil {
			t.Fatalf("resume %d: %v", n, err)
		}
	}
	if _, err = os.Stat(filepath.Join(expected, "bootstrap-postgres", "bundle.adapter.json")); err != nil {
		t.Fatal("CLI omitted corrected role from generation identity", err)
	}
	if got, _ := os.ReadFile(filepath.Join(old, "bundle.adapter.json")); !bytes.Equal(got, oldProof) {
		t.Fatal("previous generation modified")
	}
	if after, _ := os.ReadFile(filepath.Join(stage, "receipt.json")); !bytes.Equal(before, after) {
		t.Fatal("original failed receipt modified")
	}
	if ok, err := completedBootstrapComponentContinuation(stage, inventory, variables); err != nil || !ok {
		t.Fatal("new generation completion proof rejected", err)
	}
}
