package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func TestLinkedBootstrapCompletionAuthenticatesEveryComponent(t *testing.T) {
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
	inventory := map[string]any{
		"all": map[string]any{
			"children": map[string]any{
				"exits": map[string]any{"hosts": map[string]any{"exit_0": map[string]any{}, "exit_1": map[string]any{}}},
			},
		},
	}
	variables := map[string]any{"ultra_lock_directory": root}
	inventoryRaw, _ := json.Marshal(inventory)
	if err = os.WriteFile(filepath.Join(attempt, "inventory.frozen.json"), inventoryRaw, 0600); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(root, "ansible-playbook")
	source := "#!" + python + `
import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
operation=json.loads((job/'job.json').read_text())['operation']
v=json.loads((job/'variables.json').read_text())
if operation=='bootstrap':sys.exit(1)
if operation=='lifecycle':
 if not v.get('ultra_lifecycle_resume') or v.get('ultra_lifecycle_drain') or v.get('ultra_lifecycle_phase')!='applying':sys.exit(1)
 if (pathlib.Path(v['ultra_lock_directory'])/'released').exists():sys.exit(1)
r={'verified':True}
if operation=='bootstrap-exit':r.update(exit_host=v['ultra_bootstrap_exit_host'],cert_pin='a'*64)
f=job/'result.json';f.write_text(json.dumps(r));f.chmod(0o600)
`
	if err = os.WriteFile(stub, withNormalAnsibleFailure(source), 0700); err != nil {
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
	original, err := os.ReadFile(filepath.Join(stage, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	frozen, vars, baseline, err := validateBootstrapComponentContinuation(stage)
	if err != nil {
		t.Fatal(err)
	}
	if err = assertBootstrapComponentContinuationLifecycle(ctx, stage, frozen, vars, python, stub); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "released"), []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = assertBootstrapComponentContinuationLifecycle(ctx, stage, frozen, vars, python, stub); err == nil {
		t.Fatal("released lifecycle accepted")
	}
	if err = os.Remove(filepath.Join(root, "released")); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(attempt, "linked-components-0123456789abcdef")
	if err = os.Mkdir(linked, 0700); err != nil {
		t.Fatal(err)
	}
	if ok, err := completedBootstrapComponentContinuation(stage, inventory, variables); err != nil || ok {
		t.Fatal("missing proof accepted", err)
	}
	if err = runBootstrapComponentsAdapted(ctx, frozen, vars, linked, 1, stage, python, stub); err != nil {
		t.Fatal(err)
	}
	if err = publishBootstrapComponentContinuation(stage, linked, frozen, vars, baseline); err != nil {
		t.Fatal(err)
	}
	if ok, err := completedBootstrapComponentContinuation(stage, inventory, variables); err != nil || !ok {
		t.Fatal("completion rejected", err)
	}
	after, err := os.ReadFile(filepath.Join(stage, "receipt.json"))
	if err != nil || string(original) != string(after) {
		t.Fatal("parent failed receipt modified", err)
	}
	receiptPath := filepath.Join(linked, "bootstrap-exit_0", "receipt.json")
	receipt, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err = json.Unmarshal(receipt, &saved); err != nil {
		t.Fatal(err)
	}
	saved["result"].(map[string]any)["cert_pin"] = strings.Repeat("b", 64)
	changed, _ := json.Marshal(saved)
	if err = os.WriteFile(receiptPath, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if ok, err := completedBootstrapComponentContinuation(stage, inventory, variables); err == nil || ok {
		t.Fatal("changed pin accepted")
	}
	if err = os.WriteFile(receiptPath, receipt, 0600); err != nil {
		t.Fatal(err)
	}
	rollback := filepath.Join(attempt, "rollback-adoption")
	if err = os.Mkdir(rollback, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = validateBootstrapComponentContinuation(stage); err == nil {
		t.Fatal("pending rollback permits continuation")
	}
	if ok, err := completedBootstrapComponentContinuation(stage, inventory, variables); err == nil || ok {
		t.Fatal("rollback did not invalidate proof")
	}
	if err = os.Remove(rollback); err != nil {
		t.Fatal(err)
	}
	parent := map[string]any{}
	if err = json.Unmarshal(original, &parent); err != nil {
		t.Fatal(err)
	}
	parent["code"] = "different-failure"
	changed, _ = json.Marshal(parent)
	if err = os.WriteFile(filepath.Join(stage, "receipt.json"), changed, 0600); err != nil {
		t.Fatal(err)
	}
	if ok, err := completedBootstrapComponentContinuation(stage, inventory, variables); err == nil || ok {
		t.Fatal("old baseline reused after source attempt change")
	}
}
