package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

// An explicit compatibility operation links new component receipts to an old
// frozen bootstrap. Its original bundle, job and failure history stay intact.
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
	id, err := deployansible.BootstrapPostgresAdapterID()
	if err != nil {
		return deployansible.Receipt{}, err
	}
	directory := filepath.Join(filepath.Dir(stage), "linked-components-"+id)
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
