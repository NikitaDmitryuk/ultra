package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// All mutation errors return through this transaction instead of os.Exit. A
// legacy adoption restores only application files and a compatible binary; its
// primary database and durable accounting state are never rolled back.
func applyReservedBootstrap(ctx, originalCtx context.Context, p *installplan.InstallPlan, inventory map[string]any, inspection map[string]bootstrapInspection, directory, planRoot, stateRoot, python, executable, format string, release func()) (returnErr error) {
	held := true
	verified := false
	if resumed, err := resumeBootstrapFinalization(ctx, p, directory, planRoot, python, executable); resumed || err != nil {
		return err
	}
	generation, err := bootstrapMutationGeneration(directory, inventory)
	if err != nil {
		return err
	}
	defer func() {
		if returnErr == nil || verified {
			return
		}
		if _, err := os.Lstat(filepath.Join(directory, "adoption-maintenance.json")); err != nil {
			return
		}
		cleanupSource := originalCtx
		if held {
			cleanupSource = ctx
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(cleanupSource), 15*time.Minute)
		defer cancel()
		if !held {
			var err error
			cleanup, release, err = withFrozenLifecycleLock(cleanup, p, stateRoot, directory)
			if err != nil {
				returnErr = errors.Join(returnErr, errors.New("bootstrap_rollback_lease_unavailable"))
				return
			}
			defer release()
		}
		if err := ansibleResumeFrozenLifecycle(cleanup, p, inventory, directory, python, executable); err != nil {
			returnErr = errors.Join(returnErr, err)
			return
		}
		stage := bootstrapMutationStage(directory, "rollback-adoption", generation)
		_, err := deployansible.RunLocal(cleanup, "rollback-adoption", inventory, map[string]any{"ultra_lifecycle_id": lifecycleID(directory)}, stage, python, executable)
		if err != nil {
			returnErr = errors.Join(returnErr, errors.New("bootstrap_compatible_rollback_unconfirmed"))
			return
		}
		if _, err = recordBootstrapRollbackProof(directory, inventory, generation); err != nil {
			returnErr = errors.Join(returnErr, err)
			return
		}
		if err = restoreAdoptionSchedules(cleanup, inventory, directory, python, executable); err != nil {
			returnErr = errors.Join(returnErr, err)
			return
		}
		if err = ansibleLifecycle(cleanup, p, inventory, directory, python, executable, "released", false); err != nil {
			returnErr = errors.Join(returnErr, err)
		}
	}()
	if p.AdoptRuntime {
		preflight, err := os.MkdirTemp(directory, "adoption-preflight-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(preflight) //nolint:errcheck
		if _, err = deployansible.RunLocal(ctx, "adopt", inventory, map[string]any{"ultra_lock_directory": stateRoot, "ultra_adoption_rollback": generation > 1, "ultra_lifecycle_id": lifecycleID(directory)}, filepath.Join(preflight, "compare"), python, executable); err != nil {
			return err
		}
	}
	operationVars := map[string]any{"ultra_lock_directory": stateRoot}
	emitInstallEvent(format, installplan.EventStep, "", "applying Ansible bootstrap", "")
	components, engineErr := bootstrapUsesComponents(directory)
	if engineErr != nil {
		return engineErr
	}
	if p.AdoptRuntime && !components {
		return errors.New("adoption_component_anchor_required")
	}
	if !components {
		// An existing frozen monolithic job keeps its original implementation.
		linked := false
		if generation == 1 {
			var err error
			linked, err = completedBootstrapComponentContinuation(filepath.Join(directory, "apply"), inventory, operationVars)
			if err != nil {
				return err
			}
		}
		if !linked {
			if _, err := runBootstrapMutationStage(ctx, "bootstrap", inventory, operationVars, directory, "apply", generation, python, executable); err != nil {
				return err
			}
		}
	} else if err := runBootstrapComponents(ctx, inventory, operationVars, directory, generation, python, executable); err != nil {
		return err
	}
	if p.FullAutomation() && p.AdoptRuntime {
		if err := ansibleBootstrapIngress(ctx, p, inventory, bootstrapMutationStage(directory, "ingress-adopt", generation), python, executable, "adopt", operationVars, bootstrapMutationOriginalStage(directory, "ingress-adopt", generation)); err != nil {
			return err
		}
	} else if p.FullAutomation() {
		if err := ansibleBootstrapIngress(ctx, p, inventory, bootstrapMutationStage(directory, "ingress-prepare", generation), python, executable, "prepare", operationVars, bootstrapMutationOriginalStage(directory, "ingress-prepare", generation)); err != nil {
			return err
		}
		if err := ansibleBootstrapIngress(ctx, p, inventory, bootstrapMutationStage(directory, "ingress-activate", generation), python, executable, "activate", operationVars, bootstrapMutationOriginalStage(directory, "ingress-activate", generation)); err != nil {
			return err
		}
	}
	if p.Bot.Enabled {
		if _, err := runBootstrapMutationStage(ctx, "configure-bot", inventory, operationVars, directory, "bot", generation, python, executable); err != nil {
			return err
		}
	}
	if p.FullAutomation() {
		if err := ansibleBootstrapAutomationGeneration(ctx, p, inventory, directory, inspection["bridge"].Architecture, python, executable, generation); err != nil {
			return err
		}
		if err := ansibleLifecycle(ctx, p, inventory, directory, python, executable, "checking", false); err != nil {
			return err
		}
		release()
		held = false
		ctx = originalCtx
		if err := verifyBootstrapAutomation(ctx, p, inventory, directory, python, executable, generation); err != nil {
			return err
		}
	}
	verified = true
	if err := markBootstrapVerified(directory); err != nil {
		return err
	}
	_, err = resumeBootstrapFinalization(ctx, p, directory, planRoot, python, executable)
	return err
}
