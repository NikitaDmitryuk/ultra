package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func runAdoptCommand(arguments []string) {
	flags := flag.NewFlagSet("adopt", flag.ExitOnError)
	file := flags.String("config", "install.config", "canonical deployment parameters")
	releaseDirectory := flags.String("release-dir", "", "complete verified release for read-only comparison")
	prepareConfig := flags.String("prepare-config", "", "write a private schema 2 candidate from managed recovery policy; no host changes")
	_ = flags.Bool("check", true, "read-only comparison; no configuration ownership is assumed")
	_ = flags.Parse(arguments)
	p, err := installplan.LoadConfig(*file)
	exitOnErr("adopt config", err)
	legacyPreparation := *prepareConfig != ""
	if legacyPreparation && (p.Automation != nil || *releaseDirectory == "") {
		exitOnErr("adopt preparation", errors.New("legacy config and explicit verified release required"))
	}
	if *releaseDirectory != "" {
		manifest, releaseErr := verifyAutomationRelease(*releaseDirectory, "")
		exitOnErr("adopt release", releaseErr)
		if p.Automation == nil && !legacyPreparation {
			exitOnErr("adopt policy", fmt.Errorf("explicit automation policy required"))
		}
		if !legacyPreparation {
			p.Automation.ReleaseDir, err = filepath.Abs(*releaseDirectory)
			exitOnErr("adopt release path", err)
			p.Automation.Version = manifest.Version
		}
	}
	exitOnErr("adopt validation", installplan.ValidatePlan(p))
	if !legacyPreparation {
		exitOnErr("adopt artifact preflight", preflightAutomation(p))
	}
	stateRoot, err := os.UserCacheDir()
	exitOnErr("adopt state", err)
	stateRoot = filepath.Join(stateRoot, "ultra-install")
	exitOnErr("adopt private state", ensurePrivateBootstrapDirectory(stateRoot))
	directory, err := os.MkdirTemp(stateRoot, "adopt-")
	exitOnErr("adopt attempt", err)
	defer func() {
		if err := os.RemoveAll(directory); err != nil {
			fmt.Fprintln(os.Stderr, "adopt_private_cleanup_failed")
		}
	}()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	python := "/usr/bin/python3"
	runtimePlan := p
	if legacyPreparation {
		manifest, manifestErr := verifyAutomationRelease(*releaseDirectory, "")
		exitOnErr("adopt release", manifestErr)
		absolute, absoluteErr := filepath.Abs(*releaseDirectory)
		exitOnErr("adopt release path", absoluteErr)
		copy := *p
		copy.Automation = &installplan.AutomationConfig{Version: manifest.Version, ReleaseDir: absolute}
		runtimePlan = &copy
	}
	executable, err := resolveAnsibleRuntime(ctx, runtimePlan, stateRoot, os.Getenv("ULTRA_ANSIBLE_EXECUTABLE"))
	exitOnErr("adopt pinned runtime", err)
	runtimeRelease, err := pinOperatorRuntime(executable)
	exitOnErr("adopt runtime lease", err)
	defer runtimeRelease()
	ctx, release, err := deployansible.WithOperationLock(ctx, stateRoot)
	exitOnErr("adopt lease", err)
	defer release()
	inventory, inspection, err := inspectBootstrap(ctx, p, directory, python, executable, stateRoot)
	exitOnErr("adopt inspection", err)
	if legacyPreparation {
		pinPath := os.Getenv("ULTRA_INSTALL_SSH_KNOWN_HOSTS")
		if pinPath == "" {
			pinPath = filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
		}
		pinPath, err = filepath.Abs(pinPath)
		exitOnErr("adopt pins", err)
		_, candidate, prepareErr := prepareAdoptionConfig(p, inspection["bridge"], runtimePlan.Automation.Version, runtimePlan.Automation.ReleaseDir, pinPath)
		exitOnErr("adopt policy preparation", prepareErr)
		exitOnErr("adopt private candidate", writeAdoptionCandidate(*prepareConfig, candidate))
		fmt.Println("adopt: validated private schema 2 candidate prepared; no host state changed")
		return
	}
	p.Bridge.ReuseSpec = true
	inventory, err = freezeBootstrapInventory(p, inventory, inspection, directory)
	exitOnErr("adopt expected state", err)
	_, err = deployansible.RunLocal(ctx, "adopt", inventory, map[string]any{"ultra_lock_directory": stateRoot}, filepath.Join(directory, "compare"), python, executable)
	exitOnErr("read-only adoption comparison", err)
	fmt.Println("adopt: existing deployment matches pinned configuration; no host state changed")
}

// Create only: preparation cannot overwrite canonical configuration or another
// candidate. An incomplete write is removed and never reported as successful.
func writeAdoptionCandidate(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("adoption_candidate_create_failed")
	}
	success := false
	defer func() {
		if !success {
			_ = os.Remove(path)
		}
	}()
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return errors.New("adoption_candidate_write_failed")
	}
	if err = syncUpgradeDirectory(filepath.Dir(path)); err != nil {
		return errors.New("adoption_candidate_sync_failed")
	}
	success = true
	return nil
}
