// Package install contains helpers for ultra-install (SSH/SCP to bridge and exit nodes).
package install

import (
	"fmt"
	"os"
	"os/exec"
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

// RunSSH runs ssh with a single remote shell invocation (e.g. "bash", "-lc", "true").
func RunSSH(user, host, identity string, remoteWords ...string) error {
	cmd := exec.Command("ssh", sshArgs(user, host, identity, remoteWords...)...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
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
