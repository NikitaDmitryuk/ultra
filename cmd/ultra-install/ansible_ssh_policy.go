package main

import (
	"fmt"

	"github.com/NikitaDmitryuk/ultra/internal/operatorssh"
)

// Override Ansible's early ssh_args rather than trying to override its default
// ControlMaster=auto in later common_args (OpenSSH keeps the first value).
// Keep the plugin's compression default and the native operator liveness.
func bootstrapSSHArgs() string {
	p := operatorssh.DefaultPolicy
	return fmt.Sprintf(
		"-F /dev/null -C -o ControlMaster=no -o ControlPath=none -o ServerAliveInterval=%d -o ServerAliveCountMax=%d",
		p.ServerAliveIntervalSeconds,
		p.ServerAliveCountMax,
	)
}
