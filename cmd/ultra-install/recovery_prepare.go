package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"syscall"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// recoveryPreparationInputs binds preparation to the original application
// release, never to the candidate recovery tools release.
type recoveryPreparationInputs struct {
	retained   retainedPrimaryRebuildInput
	evidence   retainedReconcileEvidence
	admission  recoveryPreparationAdmission
	installers map[string]string
}

func loadRecoveryPreparationInputs(directory, config, manifest, journal string) (recoveryPreparationInputs, error) {
	var result recoveryPreparationInputs
	in, evidence, err := loadRetainedReconcile(directory, config, manifest, journal)
	if err != nil {
		return result, err
	}
	canonicalManifest, err := readRebuildInput(filepath.Join(filepath.Dir(manifest), "release-manifest.json"), false)
	if err != nil || digestSHA256(canonicalManifest) != in.ManifestSHA256 {
		return result, errors.New("recovery_preparation_original_baseline_incomplete")
	}
	baseline, err := verifyAutomationRelease(filepath.Dir(manifest), "")
	if err != nil || baseline.SchemaVersion != 1 || !hasAutomationCapability(baseline, "ansible-deploy-v1") {
		return result, errors.New("recovery_preparation_original_baseline_incomplete")
	}
	// The sealed recovery request independently identifies its original relay and
	// schema contract. A complete but unrelated local release is insufficient.
	if _, _, err = retainedReconcileRelayIdentity(in, manifest); err != nil {
		return result, err
	}
	installers := map[string]string{}
	for _, asset := range baseline.Assets {
		for _, arch := range []string{"amd64", "arm64"} {
			if asset.Name == "ultra-install-linux-"+arch {
				installers[arch] = asset.SHA
			}
		}
	}
	if len(installers) != 2 {
		return result, errors.New("recovery_preparation_original_installers_missing")
	}
	result = recoveryPreparationInputs{in, evidence, recoveryPreparationAdmission{
		Protocol: "ultra-recovery-preparation-admission-v1", FenceSHA256: evidence.Fence,
		BaselineManifestSHA256: in.ManifestSHA256, ConfigSHA256: in.ConfigSHA256, Phase: "sealed",
	}, installers}
	if in.BridgeOnly {
		return result, errors.New("bridge_reimage_supervised_preparation_required")
	}
	if !result.admission.valid() {
		return recoveryPreparationInputs{}, errors.New("recovery_preparation_binding_invalid")
	}
	return result, nil
}

// Seal is deliberately available before preparation: an old uncertain operator
// journal must first be inspected and closed through its own audited protocol.
// This command does not install tools, initialize monitor access, or run backup.
func runRecoveryPreparation(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("recovery-prepare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	directory := fs.String("state-dir", "", "successful retained recovery workspace")
	config := fs.String("config", "", "original canonical configuration")
	manifest := fs.String("manifest", "", "complete original release manifest")
	journal := fs.String("original-journal", "", "unchanged retained recovery predecessor")
	sealOnly := fs.Bool("seal-only", false, "close verified legacy dispatch origins only")
	receipt := fs.String("receipt", "", "new private seal evidence file")
	if fs.Parse(args) != nil || fs.NArg() != 0 || !*sealOnly {
		return errors.New("recovery_preparation_seal_only_required")
	}
	for _, path := range []string{*directory, *config, *manifest, *journal, *receipt} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("recovery_preparation_absolute_paths_required")
		}
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 5*time.Minute)
	defer timeout()
	// Share the canonical operator wrapper lock without changing its journal.
	lock, err := os.OpenFile(
		filepath.Join(filepath.Dir(*config), "."+filepath.Base(*config)+".manual-deploy.lock"),
		os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW,
		0600,
	)
	if err != nil {
		return errors.New("recovery_preparation_operator_lock_unavailable")
	}
	defer func() { _ = lock.Close() }()
	info, err := lock.Stat()
	if err != nil {
		return err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("recovery_preparation_operator_lock_unsafe")
	}
	if syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return errors.New("recovery_preparation_operator_busy")
	}
	in, err := loadRecoveryPreparationInputs(*directory, *config, *manifest, *journal)
	if err != nil {
		return err
	}
	p, err := installplan.LoadConfig(*config)
	if err != nil || p.Automation == nil || len(p.Exits) != 1 {
		return errors.New("recovery_preparation_config_invalid")
	}
	if err = retainedLocalCensus(); err != nil {
		return err
	}
	// Observation precedes any service mutation, then repeats under both leases.
	if err = verifyRetainedReconcilePrimary(ctx, p, in.retained); err != nil {
		return err
	}
	leases := []*recoveryPreparationAdmissionLease{}
	defer func() {
		for _, lease := range leases {
			lease.close()
		}
	}()
	for n, target := range []struct{ address, key string }{{p.Bridge.SSHHost, p.BridgeSSHIdentity()}, {p.Exits[0].SSHHost, p.ExitSSHIdentity(p.Exits[0])}} {
		role := "bridge"
		if n == 1 {
			role = "exit"
		}
		lease, e := openRecoveryPreparationAdmission(ctx, p, role, target.address, target.key, in.admission, in.installers, true)
		if e != nil {
			return e
		}
		leases = append(leases, lease)
	}
	if err = verifyRetainedReconcilePrimary(ctx, p, in.retained); err != nil {
		return err
	}
	again, err := loadRecoveryPreparationInputs(*directory, *config, *manifest, *journal)
	if err != nil || !reflect.DeepEqual(in, again) {
		return errors.New("recovery_preparation_inputs_changed")
	}
	for _, lease := range leases {
		if err = lease.recheck(); err != nil {
			return err
		}
	}
	raw, _ := json.Marshal(
		map[string]any{"protocol": "ultra-recovery-preparation-seal-v1", "admission": in.admission, "retained_evidence": in.evidence},
	)
	if err = publishRetainedReconcile(*receipt, raw); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "legacy dispatch origins sealed; recovery tools and readiness remain unprepared")
	return err
}
