package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallerCLIRejectsRemovedDirectInstallation(t *testing.T) {
	if os.Getenv("ULTRA_INSTALL_CLI_TEST") == "1" {
		for i, arg := range os.Args {
			if arg == "--" {
				os.Args = append([]string{"ultra-install"}, os.Args[i+1:]...)
				main()
				return
			}
		}
		t.Fatal("missing test command separator")
	}
	directory := t.TempDir()
	marker := filepath.Join(directory, "external-command")
	for _, name := range []string{"ssh", "scp", "ansible-playbook"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("#!/bin/sh\nprintf called > \"$ULTRA_INSTALL_CLI_MARKER\"\nexit 91\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{
		nil,
		{"-bridge", "192.0.2.10", "-exit", "192.0.2.20"},
		{"-exit-only", "-bridge", "192.0.2.10", "-exit", "192.0.2.20", "-dry-run"},
		{"unknown-command"},
		{"--help"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			command := exec.Command(
				os.Args[0],
				append([]string{"-test.run=^TestInstallerCLIRejectsRemovedDirectInstallation$", "--"}, args...)...)
			command.Env = append(os.Environ(), "ULTRA_INSTALL_CLI_TEST=1", "ULTRA_INSTALL_CLI_MARKER="+marker, "PATH="+directory)
			output, err := command.CombinedOutput()
			if len(args) == 1 && args[0] == "--help" {
				if err != nil || !strings.Contains(string(output), "Usage: ultra-install <command>") {
					t.Fatalf("help: %v %s", err, output)
				}
			} else {
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 2 || !strings.Contains(string(output), "unknown command") {
					t.Fatalf("removed interface was not rejected: %v %s", err, output)
				}
			}
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatal("unsupported command reached an external installer")
			}
		})
	}
}
