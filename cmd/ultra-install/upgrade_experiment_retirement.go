package main

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

type upgradeRetirementRunner func(context.Context, string, map[string]any, map[string]any, string, string, string) (deployansible.Receipt, error)

// Reuse the held fleet lease and immutable ingress job. Do not reenter the CLI:
// that would acquire the operator/fleet locks a second time.
func runUpgradeExperimentalRetirement(ctx context.Context, inventory, variables map[string]any,
	directory, python, executable string, retryFailed bool,
) error {
	run := deployansible.RunLocal
	if retryFailed {
		run = deployansible.RunLocalRetryFailed
	}
	return applyUpgradeExperimentalRetirement(ctx, inventory, variables, directory, python, executable, run)
}

func applyUpgradeExperimentalRetirement(ctx context.Context, inventory, variables map[string]any,
	directory, python, executable string, run upgradeRetirementRunner,
) error {
	// Retirement is independent of desired ingress changes: use observed receipt
	// and recovery metadata, never infer the old endpoint from canonical settings.
	request := map[string]any{
		"ultra_lock_directory": variables["ultra_lock_directory"],
		"ultra_ingress_action": "retire-experiment",
	}
	_, err := run(ctx, "ingress", inventory, request, filepath.Join(directory, "retire-experiment"), python, executable)
	if err != nil {
		return fmt.Errorf("upgrade_experimental_retirement_incomplete: %w", err)
	}
	return nil
}
