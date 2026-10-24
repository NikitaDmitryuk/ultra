package main

import (
	"context"
	"errors"
	"os/exec"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

const installedFleetIdentity = "/etc/ultra-fleet/id_ed25519"

// This fixed bridge-side identity must never be resolved against the operator's
// home or accepted on a machine merely claiming to be the bridge.
var attestInstalledRuntimeTransport = func(p *installplan.InstallPlan) error {
	if !p.LifecycleOnly || !localLifecycleMachineIdentity(p) || p.Automation == nil ||
		p.Automation.KnownHostsFile != "/etc/ultra-recovery/known_hosts" ||
		p.SSH.User != "root" || p.Database.SSHUser != "root" ||
		p.BridgeSSHIdentity() != installedFleetIdentity || p.Database.SSHIdentity != installedFleetIdentity {
		return errors.New("installed_runtime_transport_bridge_required")
	}
	for _, exit := range p.Exits {
		if p.ExitSSHIdentity(exit) != installedFleetIdentity {
			return errors.New("installed_runtime_transport_identity_changed")
		}
	}
	if _, err := readRebuildInput(p.Automation.KnownHostsFile, false); err != nil {
		return errors.New("installed_runtime_transport_pins_invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", recoveryPreparationFleetIdentityProgram).Run() != nil {
		return errors.New("installed_runtime_transport_identity_invalid")
	}
	return nil
}
