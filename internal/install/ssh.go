// Package install contains helpers for ultra-install (SSH/SCP to bridge and exit nodes).
package install

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func sshArgs(user, host, identity string, remoteWords ...string) []string {
	args := []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"}
	if identity != "" {
		args = append(args, "-i", identity)
	}
	args = append(args, fmt.Sprintf("%s@%s", user, host))
	args = append(args, remoteWords...)
	return args
}

// shellSingleQuote wraps s in single quotes for a POSIX shell (-lc) argument.
func shellSingleQuote(s string) string {
	return `'` + strings.ReplaceAll(s, `'`, `'"'"'`) + `'`
}

// RunSSH runs ssh with one remote argv: login bash executes script as a single -c string.
// Multiple ssh "command" tokens are unsafe: OpenSSH joins them with spaces, so
// bash -lc mv /a /b is parsed as -c mv only → "mv: missing file operand".
func RunSSH(user, host, identity string, script string) error {
	remote := "bash -lc " + shellSingleQuote(script)
	cmd := exec.Command("ssh", sshArgs(user, host, identity, remote)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// RunSSHOutput runs ssh like RunSSH but returns remote stdout (stderr still goes to os.Stderr).
func RunSSHOutput(user, host, identity string, script string) ([]byte, error) {
	remote := "bash -lc " + shellSingleQuote(script)
	cmd := exec.Command("ssh", sshArgs(user, host, identity, remote)...)
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

// SCP copies a local file to remotePath (full remote path like /etc/ultra-relay/spec.json).
func SCP(identity, local, user, host, remotePath string) error {
	args := []string{"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"}
	if identity != "" {
		args = append(args, "-i", identity)
	}
	args = append(args, local, fmt.Sprintf("%s@%s:%s", user, host, remotePath))
	cmd := exec.Command("scp", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
