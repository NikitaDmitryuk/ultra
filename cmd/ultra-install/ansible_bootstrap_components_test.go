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

func TestBootstrapComponentsResumeAndRollbackGeneration(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python unavailable")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "attempt")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	inventory := map[string]any{"all": map[string]any{"children": map[string]any{"exits": map[string]any{"hosts": map[string]any{"exit_1": map[string]any{}, "exit_0": map[string]any{}}}}}}
	vars := map[string]any{"ultra_lock_directory": root}
	stub := filepath.Join(root, "ansible-playbook")
	source := "#!" + python + `
import json,pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
meta=json.loads((job/'job.json').read_text())
vars=json.loads((job/'variables.json').read_text())
with (job.parent/'calls').open('a') as f:f.write(meta['operation']+':'+vars.get('ultra_bootstrap_exit_host','')+'\n')
result={'verified':True}
if meta['operation']=='bootstrap-exit':result.update(exit_host=vars['ultra_bootstrap_exit_host'],cert_pin='a'*64)
if meta['operation']=='bootstrap-bridge' and vars['ultra_bootstrap_pins'] != {'exit_0':'a'*64,'exit_1':'a'*64}:sys.exit(1)
f=job/'result.json';f.write_text(json.dumps(result));f.chmod(0o600)
`
	if err := os.WriteFile(stub, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := deployansible.WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for _, generation := range []int{1, 1, 2} {
		if err := runBootstrapComponents(ctx, inventory, vars, directory, generation, python, stub); err != nil {
			t.Fatal(err)
		}
	}
	calls, err := os.ReadFile(filepath.Join(directory, "calls"))
	if err != nil {
		t.Fatal(err)
	}
	want := "bootstrap-postgres:\nbootstrap-exit:exit_0\nbootstrap-exit:exit_1\nbootstrap-bridge:\n"
	if string(calls) != want+want {
		t.Fatalf("component order/cache/generation = %q", calls)
	}
	original, err := os.ReadFile(filepath.Join(directory, "bootstrap-postgres", "bundle", "controller.py"))
	if err != nil {
		t.Fatal(err)
	}
	for _, stage := range []string{"bootstrap-exit_0", "bootstrap-exit_1", "bootstrap-bridge", "bootstrap-postgres-generation-2", "bootstrap-bridge-generation-2"} {
		actual, err := os.ReadFile(filepath.Join(directory, stage, "bundle", "controller.py"))
		if err != nil || string(actual) != string(original) {
			t.Fatalf("bundle changed at %s: %v", stage, err)
		}
	}
	receiptPath := filepath.Join(directory, "bootstrap-exit_0", "receipt.json")
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var saved map[string]any
	if err = json.Unmarshal(raw, &saved); err != nil {
		t.Fatal(err)
	}
	saved["operation"] = "bootstrap-bridge"
	raw, _ = json.Marshal(saved)
	if err = os.WriteFile(receiptPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = runBootstrapComponents(ctx, inventory, vars, directory, 1, python, stub); err == nil {
		t.Fatalf("forged cache accepted: %v", err)
	}
}

func TestBootstrapComponentAliasOrderAndRejection(t *testing.T) {
	inventory := map[string]any{"all": map[string]any{"children": map[string]any{"exits": map[string]any{"hosts": map[string]any{"exit_10": nil, "exit_2": nil, "exit_0": nil}}}}}
	aliases, err := bootstrapComponentExits(inventory)
	if err != nil || strings.Join(aliases, ",") != "exit_0,exit_2,exit_10" {
		t.Fatalf("aliases %v %v", aliases, err)
	}
	all := inventory["all"].(map[string]any)
	all["children"].(map[string]any)["exits"].(map[string]any)["hosts"].(map[string]any)["exit_01"] = nil
	if _, err = bootstrapComponentExits(inventory); err == nil {
		t.Fatal("noncanonical alias accepted")
	}
}
