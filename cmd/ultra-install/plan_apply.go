package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func applyPlanN(p *installplan.InstallPlan, format string) {
	if p.Automation == nil {
		exitOnErr("controller release preflight", fmt.Errorf("independent Ansible controller requires canonical schema 2 configuration and a complete verified release; plan, render and doctor remain read-only"))
	}
	exitOnErr("automation preflight", preflightAutomation(p))
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	planJSON, err := json.Marshal(p)
	exitOnErr("bootstrap identity", err)
	planHash := sha256.Sum256(planJSON)
	stateRoot, err := bootstrapStateRoot()
	exitOnErr("bootstrap state directory", err)
	planRoot := filepath.Join(stateRoot, "bootstrap-"+hex.EncodeToString(planHash[:]))
	exitOnErr("private bootstrap state", ensurePrivateBootstrapDirectory(stateRoot))
	exitOnErr("private bootstrap workspace", ensurePrivateBootstrapDirectory(planRoot))
	executable, err := resolveAnsibleRuntime(ctx, p, stateRoot, os.Getenv("ULTRA_ANSIBLE_EXECUTABLE"))
	exitOnErr("offline Ansible runtime", err)
	runtimeRelease, err := pinOperatorRuntime(executable)
	exitOnErr("bootstrap runtime lease", err)
	defer runtimeRelease()
	originalCtx := ctx
	ctx, operatorRelease, err := withBootstrapOperatorLock(ctx, stateRoot)
	exitOnErr("bootstrap operator serialization", err)
	defer operatorRelease()
	directory, err := beginBootstrapAttempt(planRoot)
	exitOnErr("bootstrap attempt", err)
	exitOnErr("bootstrap frozen plan", freezeOperatorPlan(directory, p, p.Automation.ReleaseDir))
	operationRuntimeRelease, err := pinOperatorRuntimeForOperation(directory, executable)
	exitOnErr("bootstrap runtime reference", err)
	defer operationRuntimeRelease()
	lockDirectory, err := freezeBootstrapExecution(p, directory, stateRoot)
	exitOnErr("bootstrap execution mode", err)
	ctx, release, err := withFrozenLifecycleLock(ctx, p, lockDirectory, directory)
	exitOnErr("bootstrap operation lease", err)
	defer release()
	python := "/usr/bin/python3"
	if resumed, err := resumeBootstrapFinalization(ctx, p, directory, planRoot, python, executable); resumed || err != nil {
		exitOnErr("bootstrap finalization", err)
		emitInstallEvent(format, installplan.EventStep, "", "install finished", "")
		return
	}
	emitInstallEvent(format, installplan.EventStep, "", "inspecting pinned Ansible targets", "")
	preflightPlan := *p
	if p.AdoptRuntime {
		preflightPlan.Exits = nil
	}
	inventory, inspection, err := inspectBootstrapWithTopology(ctx, &preflightPlan, directory, python, executable, false, lockDirectory)
	exitOnErr("Ansible target inspection", err)
	// Read-only architecture discovery is allowed before the reservation. The
	// actual immutable topology/config snapshot is taken only after the broker
	// has gated and drained existing control operations.
	existingJSON, readErr := inspection["bridge"].file("spec.json")
	exitOnErr("bootstrap existing publication", readErr)
	if len(existingJSON) > 0 {
		var existing config.Spec
		exitOnErr("bootstrap existing publication", json.Unmarshal(existingJSON, &existing))
		exitOnErr("bootstrap existing publication", checkPublishedIngressPlan(p, &existing))
	}
	inventory, inspection, err = prepareReservedBootstrap(ctx, p, inventory, inspection, directory, lockDirectory, python, executable, format)
	exitOnErr("reserved Ansible bootstrap inputs", err)
	exitOnErr("Ansible bootstrap transaction", applyReservedBootstrap(ctx, originalCtx, p, inventory, inspection, directory, planRoot, lockDirectory, python, executable, format, release))
	emitInstallEvent(format, installplan.EventStep, "", "install finished", "")
}

func applyRemotePlan(p *installplan.InstallPlan, releaseDir string, format string) {
	if releaseDir == "" {
		releaseDir = "/opt/ultra/current"
	}
	if p.Automation != nil {
		manifest, err := verifyAutomationRelease(releaseDir, "")
		exitOnErr("remote controller release", err)
		p.Automation.ReleaseDir = releaseDir
		p.Automation.Version = manifest.Version
	}
	p.Artifacts.ProjectRoot = ""
	p.Artifacts.RelayBinary = filepath.Join(releaseDir, "ultra-relay")
	p.Artifacts.BotBinary = filepath.Join(releaseDir, "ultra-bot")
	applyPlanN(p, format)
}

func checkPublishedIngressPlan(p *installplan.InstallPlan, existing *config.Spec) error {
	if !p.FullAutomation() || p.Automation.Ingress == nil {
		return nil
	}
	if !existing.PrimaryXHTTPIsPublished() {
		if p.AdoptRuntime {
			return fmt.Errorf("adoption_published_ingress_required")
		}
		return nil
	}
	requested := p.Automation.Ingress
	if p.AdoptRuntime && existing.GatewayVLESSPort != requested.GatewayPort {
		return fmt.Errorf("adoption_gateway_plan_mismatch")
	}
	active := existing.PrimaryXHTTP
	if active.ServerName != requested.Domain || active.Host != requested.PublicHost || active.Path != requested.Path || active.BackendPort != requested.BackendPort || active.Port != 443 {
		return fmt.Errorf("published_ingress_change_requires_explicit_cutover")
	}
	return nil
}
