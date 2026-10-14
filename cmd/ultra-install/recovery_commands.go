package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
)

// HandleRecoveryCommand runs the bundled operator-local recovery workflow.
// The age identity remains on this operator machine, never in the SSH payload.
func HandleRecoveryCommand(args []string) bool {
	if len(args) == 0 || (args[0] != "restore" && args[0] != "recovery-key" && args[0] != "prepare-recovery-runtime") {
		return false
	}
	if err := runRecoveryCommand(args); err != nil {
		fmt.Fprintln(os.Stderr, "recovery command failed; private details suppressed")
		os.Exit(1)
	}
	return true
}

func runRecoveryCommand(args []string) error {
	if args[0] == "prepare-recovery-runtime" {
		return runPrepareRecoveryRuntime(args[1:])
	}
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
		if name.IsDir() || filepath.Ext(name.Name()) != ".py" || strings.HasPrefix(name.Name(), "test_") {
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
	executable, executableErr := os.Executable()
	if executableErr != nil {
		return executableErr
	}
	command.Env = append(os.Environ(), "ULTRA_INSTALL_BINARY="+executable)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
	return command.Run()
}

func runPrepareRecoveryRuntime(args []string) error {
	flags := flag.NewFlagSet("prepare-recovery-runtime", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	releaseDir := flags.String("release-dir", "", "complete verified release")
	archive := flags.String("runtime-archive", "", "authenticated runtime archive")
	expected := flags.String("sha256", "", "authenticated archive checksum")
	state := flags.String("state-dir", "", "private operator state")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*state) {
		return fmt.Errorf("invalid operator runtime request")
	}
	if err := ensurePrivateBootstrapDirectory(*state); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var executable string
	var err error
	if *releaseDir != "" {
		if *archive != "" || *expected != "" || !filepath.IsAbs(*releaseDir) {
			return fmt.Errorf("ambiguous operator runtime source")
		}
		p := &installplan.InstallPlan{Automation: &installplan.AutomationConfig{ReleaseDir: *releaseDir}}
		executable, err = resolveAnsibleRuntime(ctx, p, *state, "")
	} else {
		executable, err = preparePinnedAnsibleRuntime(ctx, *state, *archive, *expected)
	}
	if err != nil {
		return err
	}
	runtimeRelease, err := pinOperatorRuntime(executable)
	if err != nil {
		return err
	}
	defer runtimeRelease()
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"executable": executable})
}
