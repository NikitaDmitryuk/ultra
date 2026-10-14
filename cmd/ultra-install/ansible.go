package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func runAnsibleController(args []string) {
	flags := flag.NewFlagSet("ansible-controller", flag.ExitOnError)
	state := flags.String("state", "/var/lib/ultra-ansible", "private persistent operation state")
	socket := flags.String("socket", "/run/ultra-ansible/controller.sock", "local controller socket")
	python := flags.String("python", "/usr/bin/python3", "controller Python executable")
	executable := flags.String("executable", "/opt/ultra-ansible/current/venv/bin/ansible-playbook", "pinned Ansible executable")
	account := flags.String("allowed-user", "ultra-relay", "local submitting service account")
	_ = flags.Parse(args)
	identity, err := user.Lookup(*account)
	exitOnErr("controller account", err)
	uid, err := strconv.ParseUint(identity.Uid, 10, 32)
	exitOnErr("controller account", err)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	runtimeRelease, err := pinOperatorRuntime(*executable)
	exitOnErr("controller runtime lease", err)
	defer runtimeRelease()
	exitOnErr("Ansible controller", deployansible.Serve(ctx, *socket, *state, *python, *executable, uint32(uid)))
}

func runAnsibleExit(args []string) {
	flags := flag.NewFlagSet("ansible-exit", flag.ExitOnError)
	socket := flags.String("socket", "/run/ultra-ansible/controller.sock", "local controller socket")
	requestPath := flags.String("request", "", "private JSON exit request")
	binary := flags.String("binary", "", "pinned relay binary")
	id := flags.String("id", "", "persistent operation UUID")
	_ = flags.Parse(args)
	info, err := os.Lstat(*requestPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
		exitOnErr("Ansible request", fmt.Errorf("private regular request file required"))
	}
	raw, err := os.ReadFile(*requestPath)
	exitOnErr("Ansible request", err)
	var request deployansible.ExitRequest
	exitOnErr("Ansible request", json.Unmarshal(raw, &request))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	_, err = (deployansible.Client{Socket: *socket}).ConfigureExit(ctx, *id, *binary, request)
	exitOnErr("Ansible exit", err)
	fmt.Println("Ansible exit: ready")
}

// Operator-only adapter. The service socket never accepts arbitrary inventory.
func runAnsibleLocal(args []string) {
	flags := flag.NewFlagSet("ansible-run", flag.ExitOnError)
	operation := flags.String("operation", "", "fixed operation")
	inventoryPath := flags.String("inventory", "", "private generated inventory JSON")
	variablesPath := flags.String("variables", "", "private generated variables JSON")
	directory := flags.String("state-dir", "", "persistent private attempt directory")
	python := flags.String("python", "/usr/bin/python3", "controller Python")
	executable := flags.String("executable", "/opt/ultra-ansible/current/venv/bin/ansible-playbook", "pinned Ansible")
	_ = flags.Parse(args)
	read := func(path string) map[string]any {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1<<20 {
			exitOnErr("Ansible input", fmt.Errorf("private regular JSON file required"))
		}
		raw, err := os.ReadFile(path)
		exitOnErr("Ansible input", err)
		var result map[string]any
		exitOnErr("Ansible input", json.Unmarshal(raw, &result))
		return result
	}
	inventory, variables := read(*inventoryPath), read(*variablesPath)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	runtimeRelease, err := pinExplicitOperatorRuntime(*directory, *executable)
	exitOnErr("operation runtime lease", err)
	defer runtimeRelease()
	_, err = deployansible.RunLocal(ctx, *operation, inventory, variables, *directory, *python, *executable)
	exitOnErr("Ansible operation", err)
	fmt.Println("Ansible operation: ready")
}

// This compatibility entry point resumes an old immutable bootstrap bundle.
// Inventory and infrastructure lease come only from the original frozen job.
func runAnsibleRetryBootstrap(args []string) {
	flags := flag.NewFlagSet("ansible-retry-bootstrap", flag.ExitOnError)
	directory := flags.String("state-dir", "", "original private bootstrap stage directory")
	python := flags.String("python", "/usr/bin/python3", "controller Python")
	executable := flags.String("executable", "/opt/ultra-ansible/current/venv/bin/ansible-playbook", "pinned Ansible")
	_ = flags.Parse(args)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	runtimeRelease, err := pinExplicitOperatorRuntime(*directory, *executable)
	exitOnErr("retry runtime lease", err)
	defer runtimeRelease()
	_, err = retryFrozenBootstrapOperator(ctx, *directory, *python, *executable)
	exitOnErr("Ansible bootstrap retry", err)
	fmt.Println("Ansible bootstrap retry: ready")
}
