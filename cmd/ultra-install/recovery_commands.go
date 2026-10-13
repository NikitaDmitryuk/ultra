package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
)

// HandleRecoveryCommand runs the bundled operator-local recovery workflow.
// The age identity remains on this operator machine, never in the SSH payload.
func HandleRecoveryCommand(args []string) bool {
	if len(args) == 0 || (args[0] != "restore" && args[0] != "recovery-key") {
		return false
	}
	if err := runRecoveryCommand(args); err != nil {
		fmt.Fprintln(os.Stderr, "recovery command failed; private details suppressed")
		os.Exit(1)
	}
	return true
}

func runRecoveryCommand(args []string) error {
	directory, err := os.MkdirTemp("", "ultra-operator-recovery-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory) //nolint:errcheck
	names, err := recoveryassets.Scripts.ReadDir(".")
	if err != nil {
		return err
	}
	for _, name := range names {
		if name.IsDir() || filepath.Ext(name.Name()) != ".py" {
			continue
		}
		content, readErr := recoveryassets.Scripts.ReadFile(name.Name())
		if readErr != nil {
			return readErr
		}
		if err = os.WriteFile(filepath.Join(directory, name.Name()), content, 0o600); err != nil {
			return err
		}
	}
	script := "restore.py"
	if args[0] == "recovery-key" {
		script = "recovery_key.py"
	}
	command := exec.Command("python3", append([]string{filepath.Join(directory, script)}, args[1:]...)...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}
