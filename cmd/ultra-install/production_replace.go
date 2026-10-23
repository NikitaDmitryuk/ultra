package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

const productionReplacementAcknowledgement = "replace-non-db-preserve-postgresql"

type replacementPrimary struct {
	SystemIdentifier string                 `json:"system_identifier"`
	Database         string                 `json:"database"`
	DatabaseOID      uint32                 `json:"database_oid"`
	Migrations       string                 `json:"migrations"`
	Routes           []exits.BootstrapEntry `json:"routes"`
}

type replacementTarget struct{ Address, Identity, Role string }

type replacementSteps struct {
	Observe          func(context.Context) (replacementPrimary, error)
	Discover         func(context.Context, replacementTarget) error
	Fence            func(context.Context, replacementTarget) error
	Quiescent        func(context.Context, replacementTarget) error
	PrimaryQuiescent func(context.Context) error
	Clean            func(context.Context, replacementTarget, []exits.BootstrapEntry) error
	RetireJournal    func() error
	Bootstrap        func(context.Context) error
	Checkpoint       func(string) error
}

// Every host is discovered before the first fence; every fence is verified
// before the first cleanup. Only explicit replacement calls this transaction.
func executeProductionReplacement(
	ctx context.Context,
	targets []replacementTarget,
	expected replacementPrimary,
	steps replacementSteps,
) error {
	run := func(stage string, work func() error) error {
		if err := steps.Checkpoint(stage); err != nil {
			return err
		}
		if err := work(); err != nil {
			return fmt.Errorf("replace_production_failed: stage=%s: %w", stage, err)
		}
		return nil
	}
	check := func() error {
		actual, err := steps.Observe(ctx)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(expected, actual) {
			return errors.New("replacement_primary_schema_or_topology_changed")
		}
		return nil
	}
	quiescent := func(label string) error {
		if steps.Quiescent == nil || steps.PrimaryQuiescent == nil {
			return errors.New("replacement_quiescence_verifier_required")
		}
		for _, target := range targets {
			if err := run(label+"-"+target.Role, func() error { return steps.Quiescent(ctx, target) }); err != nil {
				return err
			}
		}
		return run(label+"-primary", func() error { return steps.PrimaryQuiescent(ctx) })
	}
	for _, target := range targets {
		if err := run("discover-"+target.Role, func() error { return steps.Discover(ctx, target) }); err != nil {
			return err
		}
	}
	if err := run("primary-before-fence", check); err != nil {
		return err
	}
	for _, target := range targets {
		if err := run("fence-"+target.Role, func() error { return steps.Fence(ctx, target) }); err != nil {
			return err
		}
	}
	// The primary identity/schema was captured before fencing. Fencing only
	// targets non-DB hosts, so avoid opening a second primary SSH session here;
	// the immediately following primary gate checks active transactions and
	// must see unrelated root sessions without our own probe tail.
	if err := quiescent("quiescence-before-cleanup"); err != nil {
		return err
	}
	for _, target := range targets {
		if err := run("clean-"+target.Role, func() error { return steps.Clean(ctx, target, expected.Routes) }); err != nil {
			return err
		}
	}
	if err := quiescent("quiescence-after-cleanup"); err != nil {
		return err
	}
	if err := quiescent("quiescence-before-journal"); err != nil {
		return err
	}
	if err := run("retire-local-journal", steps.RetireJournal); err != nil {
		return err
	}
	if err := run("bootstrap", func() error { return steps.Bootstrap(ctx) }); err != nil {
		return err
	}
	if err := run("primary-after-bootstrap", check); err != nil {
		return err
	}
	return steps.Checkpoint("completed")
}

func replacementTargets(p *installplan.InstallPlan) ([]replacementTarget, error) {
	if p.BridgeNative || localLifecycleBridge(p) || p.Database.PrimaryHost == "" {
		return nil, errors.New("replacement_remote_dedicated_primary_required")
	}
	targets := []replacementTarget{{p.Bridge.SSHHost, p.BridgeSSHIdentity(), "bridge"}}
	seen := map[string]bool{p.Bridge.SSHHost: true}
	for n, exit := range p.Exits {
		if seen[exit.SSHHost] {
			return nil, errors.New("replacement_duplicate_target")
		}
		seen[exit.SSHHost] = true
		targets = append(targets, replacementTarget{exit.SSHHost, p.ExitSSHIdentity(exit), "exit-" + strconv.Itoa(n)})
	}
	for _, target := range targets {
		if target.Identity == "" || samePreservedPrimaryHost(target.Address, p.Database.PrimaryHost) {
			return nil, errors.New("replacement_primary_in_destructive_inventory")
		}
	}
	return targets, nil
}

func observeReplacementPrimary(ctx context.Context, p *installplan.InstallPlan) (replacementPrimary, error) {
	key := p.Database.SSHIdentity
	if key == "" {
		key = p.SSH.Identity
	}
	raw, err := retainedRemote(ctx, p, p.Database.PrimaryHost, key, true, replacementPrimaryProgram, []string{p.Database.Name})
	var observed replacementPrimary
	if err != nil {
		return observed, err
	}
	if json.Unmarshal(raw, &observed) != nil || observed.Database != p.Database.Name || observed.SystemIdentifier == "" ||
		observed.DatabaseOID == 0 ||
		observed.Migrations == "" {
		return observed, errors.New("replacement_primary_observation_invalid")
	}
	return observed, nil
}

func validateReplacementTopology(p *installplan.InstallPlan, observed replacementPrimary, schemaMax int) error {
	if schemaMax < 1 || schemaMax > 10000 {
		return errors.New("replacement_schema_contract_invalid")
	}
	want := make([]string, schemaMax)
	for n := range want {
		want[n] = strconv.Itoa(n + 1)
	}
	if observed.Migrations != strings.Join(want, ",") {
		return errors.New("replacement_candidate_would_change_schema")
	}
	managedRoutes, err := managedPreservedPrimaryRoutes(p, observed.Routes)
	if err != nil {
		return errors.New("replacement_authoritative_topology_mismatch")
	}
	desired, err := installplan.RenderDesiredStateWithOptions(p, installplan.RenderOptions{PriorBootstrap: observed.Routes})
	if err != nil {
		return fmt.Errorf("replacement_render_preflight: %w", err)
	}
	if err = comparePreservedRouteIdentities(desired.Bootstrap, managedRoutes); err != nil {
		return err
	}
	return nil
}

func runProductionReplacement(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("replace-production", flag.ContinueOnError)
	flags.SetOutput(output)
	config := flags.String("config", "", "canonical config already pinned to the candidate")
	backup := flags.String("primary-backup", "", "fresh encrypted primary backup")
	backupMaxAge := flags.Duration("primary-backup-max-age", defaultPrimaryBackupMaxAge, "maximum verified primary backup and restore age (whole seconds, at most 24h)")
	backupSHA := flags.String("primary-backup-sha256", "", "exact encrypted backup digest")
	commit := flags.String("source-commit", "", "exact candidate source commit")
	manifestSHA := flags.String("manifest-sha256", "", "exact candidate manifest digest")
	state := flags.String("state-dir", "", "new private replacement workspace")
	journal := flags.String("manual-journal", "", "exact obsolete local manual journal")
	previousConfig := flags.String("previous-config", "", "exact config bytes pinned by the dispatched journal")
	restoreReceipt := flags.String("primary-restore-receipt", "", "private receipt from real isolated PostgreSQL restore of this backup")
	ack := flags.String("acknowledge", "", "required destructive non-DB scope acknowledgment")
	if err := flags.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return errors.New("replacement_arguments_invalid")
	}
	if err := validatePrimaryBackupMaxAge(*backupMaxAge); err != nil {
		return err
	}
	if flags.NArg() != 0 || *ack != productionReplacementAcknowledgement {
		return errors.New("replacement_explicit_scope_required")
	}
	for _, path := range []string{*config, *backup, *state, *journal, *restoreReceipt} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("replacement_absolute_paths_required")
		}
	}
	if *journal != filepath.Join(filepath.Dir(*config), "dist", "manual", "operation.json") {
		return errors.New("replacement_manual_journal_scope_invalid")
	}
	localExecutionState, err := deployansible.ExpectedLocalExecutionState()
	if err != nil {
		return fmt.Errorf("replacement_local_execution_state: %w", err)
	}
	if err = deployansible.ConfigureLocalExecutionState(localExecutionState); err != nil {
		return fmt.Errorf("replacement_local_execution_state: %w", err)
	}
	if err := deployansible.PreflightLocalExecution(); err != nil {
		return fmt.Errorf("replacement_local_execution_preflight: %w", err)
	}
	configRaw, err := readRebuildInput(*config, true)
	if err != nil {
		return err
	}
	p, err := installplan.LoadConfig(*config)
	if err != nil {
		return errors.New("replacement_config_invalid")
	}
	if err = authorizePreservedPrimaryBootstrap(p, *backup, *backupSHA, *backupMaxAge); err != nil {
		return err
	}
	if p.Bridge.ReuseSpec {
		return errors.New("replacement_requires_fresh_bootstrap_config")
	}
	if err = installplan.ValidateBootstrapPlan(p); err != nil {
		return err
	}
	manifest, err := verifyOperatorUpgradeRelease(p.Automation.ReleaseDir, *commit, p.Automation.Version, *manifestSHA, "/proc/self/exe")
	if err != nil {
		return err
	}
	verifiedBackup, err := verifyRetainedBackupBundle(
		*backup,
		*backupSHA,
		p.SourceValues["ULTRA_OPERATOR_AGE_IDENTITY_FILE"],
		retainedSourceSHA256(p.Database.PrimaryHost, p.Database.Name),
		p.Database.Name,
		*backupMaxAge,
		time.Now(),
	)
	if err != nil {
		return err
	}
	receiptRaw, err := readRebuildInput(*restoreReceipt, true)
	if err != nil {
		return errors.New("replacement_isolated_restore_receipt_required")
	}
	if err = validateReplacementRestoreReceipt(receiptRaw, verifiedBackup, p.Database.Name, manifest.DatabaseSchemaMax, *backupMaxAge, time.Now()); err != nil {
		return err
	}
	if _, err = installplan.ReadPlanSecrets(p); err != nil {
		return errors.New("replacement_canonical_application_secrets_unavailable")
	}
	targets, err := replacementTargets(p)
	if err != nil {
		return err
	}
	lock, err := openOperatorLock(
		filepath.Join(filepath.Dir(*config), "."+filepath.Base(*config)+".manual-deploy.lock"),
		uint32(os.Geteuid()),
	)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	if err = replacementLocalQuiescence(); err != nil {
		return err
	}
	journalRaw, err := replacementJournalInput(*journal)
	if err != nil {
		return err
	}
	targets, err = replacementPreviousTargets(journalRaw, *previousConfig, p, targets)
	if err != nil {
		return err
	}
	current, err := readRebuildInput(*config, true)
	if err != nil || string(current) != string(configRaw) {
		return errors.New("replacement_config_changed")
	}
	if err = os.Mkdir(*state, 0700); err != nil {
		return errors.New("replacement_new_workspace_required")
	}
	if err = replaceUpgradeMetadata(filepath.Join(*state, "config.original"), configRaw); err != nil {
		return err
	}
	if err = replaceUpgradeMetadata(filepath.Join(*state, "isolated-restore-receipt.json"), receiptRaw); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	observe := func(ctx context.Context) (replacementPrimary, error) { return observeReplacementPrimary(ctx, p) }
	before, err := observe(ctx)
	if err != nil {
		return err
	}
	if err = validateReplacementTopology(p, before, manifest.DatabaseSchemaMax); err != nil {
		return err
	}
	routesRaw, _ := json.Marshal(before.Routes)
	targetsRaw, _ := json.Marshal(targets)
	if err = replaceUpgradeMetadata(filepath.Join(*state, "targets.json"), targetsRaw); err != nil {
		return err
	}
	if err = replaceUpgradeMetadata(filepath.Join(*state, "primary-before.json"), mustReplacementJSON(before)); err != nil {
		return err
	}
	remote := func(ctx context.Context, target replacementTarget, mode string) error {
		parameters := []string{mode, target.Role, digestSHA256(configRaw), p.Database.PrimaryHost, string(routesRaw)}
		var raw []byte
		var err error
		if mode == "discover" {
			raw, err = retainedRemote(ctx, p, target.Address, target.Identity, false, replacementHostProgram, parameters)
		} else {
			raw, err = retainedMutation(ctx, p, target.Address, target.Identity, false, replacementHostProgram, parameters)
		}
		if err != nil {
			return err
		}
		var receipt struct {
			State   string `json:"state"`
			Binding string `json:"binding"`
		}
		if json.Unmarshal(raw, &receipt) != nil || receipt.State != mode || receipt.Binding != digestSHA256(configRaw) {
			return errors.New("replacement_host_receipt_invalid")
		}
		return replaceUpgradeMetadata(filepath.Join(*state, mode+"-"+target.Role+".json"), raw)
	}
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	steps := replacementSteps{
		Observe:  observe,
		Discover: func(ctx context.Context, target replacementTarget) error { return remote(ctx, target, "discover") },
		Fence:    func(ctx context.Context, target replacementTarget) error { return remote(ctx, target, "fence") },
		Quiescent: func(ctx context.Context, target replacementTarget) error {
			return checkReplacementQuiescence(ctx, p, target, false)
		},
		PrimaryQuiescent: func(ctx context.Context) error {
			identity := p.Database.SSHIdentity
			if identity == "" {
				identity = p.SSH.Identity
			}
			return checkReplacementQuiescence(
				ctx,
				p,
				replacementTarget{Address: p.Database.PrimaryHost, Identity: identity, Role: "primary"},
				true,
			)
		},
		Clean: func(ctx context.Context, target replacementTarget, _ []exits.BootstrapEntry) error {
			return remote(ctx, target, "clean")
		},
		Checkpoint: func(stage string) error {
			fmt.Fprintln(output, "replace-production: "+stage)
			return replaceUpgradeMetadata(
				filepath.Join(*state, "stage.json"),
				mustReplacementJSON(
					map[string]string{
						"stage":           stage,
						"config_sha256":   digestSHA256(configRaw),
						"manifest_sha256": *manifestSHA,
						"backup_sha256":   *backupSHA,
					},
				),
			)
		},
		RetireJournal: func() error {
			raw, err := replacementJournalInput(*journal)
			if err != nil {
				return err
			}
			if string(raw) != string(journalRaw) {
				return errors.New("replacement_previous_journal_changed")
			}
			if len(raw) == 0 {
				return nil
			}
			if err = replaceUpgradeMetadata(filepath.Join(*state, "discarded-manual-journal.json"), raw); err != nil {
				return err
			}
			if err = os.Remove(*journal); err != nil {
				return err
			}
			return syncUpgradeDirectory(filepath.Dir(*journal))
		},
		Bootstrap: func(ctx context.Context) error {
			child := exec.CommandContext(
				ctx,
				executable,
				productionReplacementBootstrapArgs(*config, *backup, *backupSHA, localExecutionState, *backupMaxAge)...)
			child.Env = append(os.Environ(), "ULTRA_INSTALL_STATE_DIR="+filepath.Join(*state, "bootstrap"))
			child.Stdout = output
			child.Stderr = os.Stderr
			return child.Run()
		},
	}
	return executeProductionReplacement(ctx, targets, before, steps)
}

func productionReplacementBootstrapArgs(config, backup, backupSHA, operatorState string, maxAge time.Duration) []string {
	return []string{
		"bootstrap",
		"--config",
		config,
		"--preserve-primary",
		"--primary-backup",
		backup,
		"--primary-backup-sha256",
		backupSHA,
		"--operator-state-dir",
		operatorState,
		"--primary-backup-max-age",
		maxAge.String(),
	}
}

func mustReplacementJSON(value any) []byte { raw, _ := json.Marshal(value); return raw }

func replacementLocalQuiescence() error {
	ancestors := map[string]bool{}
	for pid := os.Getpid(); pid > 0; {
		key := strconv.Itoa(pid)
		ancestors[key] = true
		raw, err := os.ReadFile(filepath.Join("/proc", key, "stat"))
		if err != nil {
			return errors.New("replacement_local_process_census_unavailable")
		}
		parts := strings.SplitN(string(raw), ") ", 2)
		if len(parts) != 2 {
			return errors.New("replacement_local_process_census_invalid")
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 2 {
			return errors.New("replacement_local_process_census_invalid")
		}
		next, err := strconv.Atoi(fields[1])
		if err != nil || next == pid {
			return errors.New("replacement_local_process_census_invalid")
		}
		pid = next
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil || ancestors[entry.Name()] {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return errors.New("replacement_local_process_census_unavailable")
		}
		for _, arg := range strings.Split(string(raw), "\x00") {
			name := filepath.Base(arg)
			if name == "ultra-install" || strings.HasPrefix(name, "ultra-install-linux-") || name == "manual-deploy.py" ||
				name == "ansible-playbook" ||
				name == "controller.py" {
				return errors.New("replacement_old_local_executor_active")
			}
		}
	}
	return nil
}
