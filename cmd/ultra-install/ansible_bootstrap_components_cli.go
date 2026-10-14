package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

// An explicit compatibility operation links new component receipts to an old
// frozen bootstrap. The old job, source roles and its failure history stay intact.
func runAnsibleBootstrapComponents(args []string) {
	flags := flag.NewFlagSet("ansible-bootstrap-components", flag.ExitOnError)
	stage := flags.String("state-dir", "", "original private failed bootstrap stage")
	python := flags.String("python", "/usr/bin/python3", "controller Python")
	executable := flags.String("executable", "/opt/ultra-ansible/current/venv/bin/ansible-playbook", "pinned Ansible")
	_ = flags.Parse(args)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	runtimeRelease, err := pinExplicitOperatorRuntime(*stage, *executable)
	exitOnErr("components runtime lease", err)
	defer runtimeRelease()
	_, err = withFrozenBootstrapStageLease(ctx, *stage, func(locked context.Context) (deployansible.Receipt, error) {
		return resumeBootstrapComponents(locked, *stage, *python, *executable)
	})
	exitOnErr("Ansible bootstrap components", err)
	fmt.Println("Ansible bootstrap components: ready; original job preserved")
}

func resumeBootstrapComponents(ctx context.Context, stage, python, executable string) (deployansible.Receipt, error) {
	inventory, variables, baseline, err := validateBootstrapComponentContinuation(stage)
	if err != nil {
		return deployansible.Receipt{}, err
	}
	if err = assertBootstrapComponentContinuationLifecycle(ctx, stage, inventory, variables, python, executable); err != nil {
		return deployansible.Receipt{}, err
	}
	id := sha256.New()
	for _, name := range []string{"controller.py", "playbooks/bootstrap-postgres.yml", "playbooks/bootstrap-exit.yml", "playbooks/bootstrap-bridge.yml"} {
		data, err := ansibleassets.Bundle.ReadFile(name)
		if err != nil {
			return deployansible.Receipt{}, err
		}
		_, _ = id.Write([]byte(name + "\x00"))
		_, _ = id.Write(data)
	}
	directory := filepath.Join(filepath.Dir(stage), "linked-components-"+hex.EncodeToString(id.Sum(nil))[:16])
	if err := ensurePrivateBootstrapDirectory(directory); err != nil {
		return deployansible.Receipt{}, err
	}
	if err = runBootstrapComponentsAdapted(ctx, inventory, variables, directory, 1, stage, python, executable); err != nil {
		return deployansible.Receipt{}, err
	}
	if err = publishBootstrapComponentContinuation(stage, directory, inventory, variables, baseline); err != nil {
		return deployansible.Receipt{}, err
	}
	return deployansible.Receipt{State: "succeeded", Result: deployansible.Result{Values: map[string]any{"verified": true}}}, nil
}
