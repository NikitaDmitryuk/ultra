package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"time"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type migrationMachine struct {
	PythonABI          string `json:"python_abi"`
	CPUCount           int    `json:"cpu_count"`
	MachineID          string `json:"machine_id"`
	Architecture       string `json:"architecture"`
	OSVersion          string `json:"os_version"`
	OS                 string `json:"os"`
	MemoryBytes        int64  `json:"memory_bytes"`
	FreeBytes          int64  `json:"free_bytes"`
	StateBytes         int64  `json:"state_bytes"`
	DatabaseBytes      int64  `json:"database_bytes"`
	PGUnit             string `json:"pg_unit"`
	PGMajor            int    `json:"pg_major"`
	ForwardHost        string `json:"forward_host"`
	SubscriptionDomain string `json:"subscription_domain"`
	BridgeAddress      string `json:"bridge_address"`
	PublicHost         string `json:"public_host"`
}

type migrationState struct {
	Pair      string           `json:"pair"`
	Phase     string           `json:"phase"`
	Source    migrationMachine `json:"source"`
	Target    migrationMachine `json:"target"`
	Activated bool             `json:"activated"`
}

type migrationOptions struct {
	Phase, Config, SourceHost, TargetHost, SourceUser, TargetUser, SourceIdentity, TargetIdentity, Pins, NewPublicHost, NewIP, Provider, AgeIdentity, Directory, Confirm, Python, Ansible, ProbeURL, ExpectedIP string
	NetworkReady, NetworkRestored, AllowDataLoss                                                                                                                                                                bool
}

func runBridgeMigrationCommand(args []string) {
	if len(args) == 0 {
		exitOnErr("bridge migration", errors.New("migration_phase_required"))
		return
	}
	fs := flag.NewFlagSet("bridge-migrate", flag.ExitOnError)
	options := migrationOptions{Phase: args[0]}
	fs.StringVar(&options.Config, "config", "", "canonical deployment parameters")
	fs.StringVar(&options.SourceHost, "source-host", "", "stable old operator SSH endpoint")
	fs.StringVar(&options.TargetHost, "target-host", "", "dedicated new operator SSH endpoint")
	fs.StringVar(&options.SourceUser, "source-user", "root", "source SSH account")
	fs.StringVar(&options.TargetUser, "target-user", "root", "target SSH account")
	fs.StringVar(&options.SourceIdentity, "source-identity", "", "source identity reference")
	fs.StringVar(&options.TargetIdentity, "target-identity", "", "target identity reference")
	fs.StringVar(&options.Pins, "known-hosts", "", "verified operator known hosts")
	fs.StringVar(&options.NewPublicHost, "new-public-host", "", "preserve the current public host when omitted")
	fs.StringVar(&options.NewIP, "new-bridge-ip", "", "new bridge address")
	fs.StringVar(&options.Provider, "new-bridge-provider", "", "new provider for recovery independence")
	fs.StringVar(&options.AgeIdentity, "age-identity", "", "operator-only offline age identity reference")
	fs.StringVar(&options.Directory, "job-dir", "", "private persistent migration receipts")
	fs.StringVar(&options.Confirm, "confirm", "", "explicit FREEZE, ACTIVATE or ROLLBACK")
	fs.StringVar(&options.Python, "python", "/usr/bin/python3", "operator Python")
	fs.StringVar(&options.Ansible, "ansible-playbook", "", "pinned Ansible executable")
	fs.StringVar(&options.ProbeURL, "verify-ip-url", "", "HTTPS egress IP endpoint")
	fs.StringVar(&options.ExpectedIP, "expected-exit-ip", "", "expected exit egress IP")
	fs.BoolVar(&options.NetworkReady, "network-ready", false, "public route points at target")
	fs.BoolVar(&options.NetworkRestored, "network-restored", false, "public route points back at source")
	fs.BoolVar(&options.AllowDataLoss, "allow-post-activate-data-loss", false, "explicitly permit acceptance-window writes to be lost on rollback")
	_ = fs.Parse(args[1:])
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	exitOnErr("bridge migration", bridgeMigration(ctx, options))
}

func bridgeMigration(ctx context.Context, o migrationOptions) error {
	if err := validateMigrationOptions(o); err != nil {
		return err
	}
	p, err := installplan.LoadConfig(o.Config)
	if err != nil {
		return err
	}
	if err = installplan.ValidatePlan(p); err != nil {
		return err
	}
	if o.SourceIdentity == "" {
		o.SourceIdentity = p.SSH.Identity
	}
	if o.TargetIdentity == "" {
		o.TargetIdentity = p.SSH.Identity
	}
	if o.Pins == "" && p.Automation != nil {
		o.Pins = p.Automation.KnownHostsFile
	}
	if o.Pins == "" {
		return errors.New("migration_verified_pins_required")
	}
	for _, path := range []string{o.Pins, o.SourceIdentity, o.TargetIdentity} {
		info, readErr := os.Stat(path)
		if !filepath.IsAbs(path) || readErr != nil || !info.Mode().IsRegular() {
			return errors.New("migration_absolute_verified_ssh_files_required")
		}
	}
	if o.Phase == "freeze" {
		info, keyErr := os.Lstat(o.AgeIdentity)
		if !filepath.IsAbs(o.AgeIdentity) || keyErr != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return errors.New("migration_private_offline_age_identity_required")
		}
	}
	directory, err := filepath.Abs(o.Directory)
	if err != nil {
		return err
	}
	if err = ensurePrivateBootstrapDirectory(directory); err != nil {
		return err
	}
	operatorCtx := ctx
	sourcePlan := migrationEndpointPlan(p, o, false)
	lockedCtx, releaseOperator, err := withBootstrapOperatorLock(ctx, filepath.Dir(directory))
	if err != nil {
		return err
	}
	defer releaseOperator()
	lockRoot, err := freezeBootstrapExecution(sourcePlan, directory, filepath.Dir(directory))
	if err != nil {
		return err
	}
	o.Ansible, err = resolveAnsibleRuntime(ctx, p, lockRoot, o.Ansible)
	if err != nil {
		return err
	}
	runtimeRelease, err := pinOperatorRuntimeForOperation(directory, o.Ansible)
	if err != nil {
		return err
	}
	defer runtimeRelease()
	ctx, release, err := withFrozenLifecycleLock(lockedCtx, sourcePlan, lockRoot, directory)
	if err != nil {
		return err
	}
	defer release()
	inventory := migrationInventory(o)
	variables := map[string]any{"ultra_lock_directory": lockRoot, "ultra_migration_local_directory": directory}
	statePath := filepath.Join(directory, "migration.json")
	var state migrationState
	raw, readErr := os.ReadFile(statePath)
	if readErr == nil {
		if json.Unmarshal(raw, &state) != nil {
			return errors.New("migration_receipt_invalid")
		}
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	binding, _ := json.Marshal(map[string]string{"source": o.SourceHost, "target": o.TargetHost, "source_user": o.SourceUser, "target_user": o.TargetUser, "source_identity": o.SourceIdentity, "target_identity": o.TargetIdentity, "pins": o.Pins})
	if err = writeUpgradeInput(filepath.Join(directory, "endpoints.json"), binding); err != nil {
		return err
	}
	if state.Pair == "" {
		if o.Phase != "preflight" && o.Phase != "stage" {
			return errors.New("migration_preflight_required")
		}
		if _, err = deployansible.RunLocal(ctx, "bridge-migrate-inspect", inventory, variables, filepath.Join(directory, "inspect"), o.Python, o.Ansible); err != nil {
			return err
		}
		for alias, target := range map[string]*migrationMachine{"source": &state.Source, "target": &state.Target} {
			raw, err = os.ReadFile(filepath.Join(directory, alias+".json"))
			if err != nil || json.Unmarshal(raw, target) != nil {
				return errors.New("migration_inventory_invalid")
			}
		}
		if err = validateMigrationMachines(state.Source, state.Target); err != nil {
			return err
		}
		hash := sha256.Sum256([]byte(state.Source.MachineID + "\x00" + state.Target.MachineID))
		state.Pair = hex.EncodeToString(hash[:])
		state.Phase = "preflight"
		if err = saveMigrationState(statePath, state); err != nil {
			return err
		}
	}
	if o.Phase == "preflight" {
		fmt.Println("bridge migration: preflight verified")
		return nil
	}
	variables["ultra_migration_pg_unit"] = state.Source.PGUnit
	variables["ultra_migration_pair"] = state.Pair
	variables["ultra_migration_source_machine_id"] = state.Source.MachineID
	variables["ultra_migration_target_machine_id"] = state.Target.MachineID
	variables["ultra_migration_confirm"] = o.Confirm
	variables["ultra_migration_network_restored"] = o.NetworkRestored
	variables["ultra_migration_app_units"] = []string{"ultra-relay.service", "ultra-bot.service"}
	variables["ultra_migration_automation_units"] = []string{"ultra-ansible-controller.service", "ultra-recovery-prune.service", "ultra-recovery-prune.timer", "ultra-recovery-backup.timer", "ultra-recovery-backup.service", "ultra-recovery-reconcile.timer", "ultra-recovery-reconcile.service", "ultra-monitor.service", "ultra-monitor.timer", "ultra-monitor-probe.service", "certbot.service", "certbot.timer"}
	variables["ultra_migration_probe_executable"] = "/opt/ultra-ansible/current/ultra-install"
	call := func(phase string) error {
		inputs := map[string]any{}
		for key, value := range variables {
			inputs[key] = value
		}
		inputs["ultra_migration_phase"] = phase
		attempt := filepath.Join(directory, "phase-"+phase)
		if phase == "stop-target" || phase == "rollback-source" || phase == "resume-target" {
			fresh, err := os.MkdirTemp(directory, "phase-"+phase+"-")
			if err != nil {
				return err
			}
			_ = os.Remove(fresh)
			attempt = fresh
		}
		_, err := deployansible.RunLocal(ctx, "bridge-migrate", inventory, inputs, attempt, o.Python, o.Ansible)
		return err
	}
	defer func() {
		if state.Phase == "rolled_back" {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
			defer cancel()
			_ = ansibleLifecycle(cleanup, sourcePlan, migrationLifecycleInventory(o, false), directory, o.Python, o.Ansible, "released", false)
		}
	}()
	switch o.Phase {
	case "stage":
		if state.Phase != "preflight" && state.Phase != "staged" {
			return errors.New("migration_stage_after_cutover_forbidden")
		}
		if err = call("stage"); err == nil {
			state.Phase = "staged"
		}
	case "freeze":
		if state.Phase != "staged" && state.Phase != "freezing" {
			return errors.New("migration_staged_target_required")
		}
		state.Phase = "freezing"
		if err = saveMigrationState(statePath, state); err != nil {
			return err
		}
		if err = ansibleLifecycle(ctx, sourcePlan, migrationLifecycleInventory(o, false), directory, o.Python, o.Ansible, "applying", true); err != nil {
			return err
		}
		if err = call("freeze"); err != nil {
			return recoverMigrationFreeze(err, &state, statePath, variables, call)
		}
		if err = prepareMigrationGeneration(ctx, o, p, directory, state); err != nil {
			return recoverMigrationFreeze(err, &state, statePath, variables, call)
		}
		if err = migrationRestorePhases(ctx, o, directory, variables, []string{"prepare", "install", "database"}); err != nil {
			return recoverMigrationFreeze(err, &state, statePath, variables, call)
		}
		state.Phase = "frozen"
	case "activate":
		if state.Phase != "frozen" && state.Phase != "activation_failed" && state.Phase != "activating" && state.Phase != "activated" {
			return errors.New("migration_frozen_generation_required")
		}
		state.Phase = "activating"
		if err = saveMigrationState(statePath, state); err != nil {
			return err
		}
		var prepared struct {
			Plan map[string]any `json:"plan"`
		}
		raw, err = os.ReadFile(filepath.Join(directory, "restore-plan.json"))
		if err != nil || json.Unmarshal(raw, &prepared) != nil {
			return errors.New("migration_restore_plan_unavailable")
		}
		variables["ultra_migration_restore_id"] = prepared.Plan["restore_id"]
		if err = migrationRefreshFence(ctx, o, directory, variables, prepared.Plan); err != nil {
			return err
		}
		if err = call("resume-target"); err != nil {
			return err
		}
		variables["ultra_restore_defer_bot"] = true
		if err = activateMigrationServices(func(phase string) error { return migrationRestorePhases(ctx, o, directory, variables, []string{phase}) }, func() error { return migrationPayloadProbe(ctx, o, directory, variables) }, func() error { return call("stop-target") }); err != nil {
			state.Phase = "activation_failed"
			_ = saveMigrationState(statePath, state)
			return err
		}
		state.Activated = true
		state.Phase = "activated"
		if err = saveMigrationState(statePath, state); err != nil {
			return err
		}
		if err = migrationIngress(ctx, o, directory, variables); err != nil {
			_ = call("stop-target")
			return err
		}
		targetPlan := migrationTargetPlan(p, o)
		if err = migrationRestorePhases(ctx, o, directory, variables, []string{"migration-controller"}); err != nil {
			return err
		}
		if err = ansibleLifecycle(ctx, targetPlan, migrationLifecycleInventory(o, true), directory, o.Python, o.Ansible, "applying", true); err != nil {
			return err
		}
		if err = migrationRestorePhases(ctx, o, directory, variables, []string{"automation"}); err != nil {
			_ = call("stop-target")
			return err
		}
		if err = ansibleLifecycle(ctx, targetPlan, migrationLifecycleInventory(o, true), directory, o.Python, o.Ansible, "checking", false); err != nil {
			return err
		}
		release()
		ctx = operatorCtx
		if err = migrationReady(ctx, o, directory, variables); err != nil {
			return err
		}
		if err = ansibleLifecycle(ctx, targetPlan, migrationLifecycleInventory(o, true), directory, o.Python, o.Ansible, "released", false); err != nil {
			return err
		}
		state.Phase = "verified"
	case "verify":
		if state.Phase != "activated" && state.Phase != "verified" {
			return errors.New("migration_activated_target_required")
		}
		if err = migrationPayloadProbe(ctx, o, directory, variables); err != nil {
			return err
		}
		release()
		ctx = operatorCtx
		if err = migrationReady(ctx, o, directory, variables); err != nil {
			return err
		}
		if err = ansibleLifecycle(ctx, migrationTargetPlan(p, o), migrationLifecycleInventory(o, true), directory, o.Python, o.Ansible, "released", false); err != nil {
			return err
		}
		state.Phase = "verified"
	case "rollback":
		if state.Phase == "preflight" || state.Phase == "rolled_back" {
			return errors.New("migration_nothing_to_rollback")
		}
		if state.Activated || state.Phase == "activating" || state.Phase == "activation_failed" {
			if !o.AllowDataLoss {
				return errors.New("migration_post_activation_data_loss_permission_required")
			}
		}
		if err = call("stop-target"); err != nil {
			return err
		}
		if state.Phase == "staged" {
			state.Phase = "rolled_back"
			break
		}
		if !o.NetworkRestored {
			state.Phase = "rollback_pending"
			break
		}
		variables["ultra_migration_defer_automation"] = state.Activated || state.Phase == "activating" || state.Phase == "activation_failed" || state.Phase == "rollback_pending"
		if err = call("rollback-source"); err != nil {
			return err
		}
		if variables["ultra_migration_defer_automation"] == true {
			if err = migrationReverseReplicas(ctx, o, directory, state, variables); err != nil {
				return err
			}
			variables["ultra_migration_defer_automation"] = false
			if err = call("rollback-source"); err != nil {
				return err
			}
		}
		if err = ansibleLifecycle(ctx, sourcePlan, migrationLifecycleInventory(o, false), directory, o.Python, o.Ansible, "released", false); err != nil {
			return err
		}
		state.Phase = "rolled_back"
	}
	if err != nil {
		return err
	}
	if err = saveMigrationState(statePath, state); err != nil {
		return err
	}
	fmt.Println("bridge migration:", state.Phase)
	return nil
}

func validateMigrationOptions(o migrationOptions) error {
	allowed := map[string]bool{"preflight": true, "stage": true, "freeze": true, "activate": true, "verify": true, "rollback": true}
	if !allowed[o.Phase] || o.Config == "" || o.Directory == "" || o.SourceHost == "" || o.TargetHost == "" || o.SourceHost == o.TargetHost {
		return errors.New("migration_distinct_endpoints_and_private_job_required")
	}
	for _, value := range []string{o.SourceHost, o.TargetHost, o.SourceUser, o.TargetUser} {
		if !regexp.MustCompile(`^[A-Za-z0-9_.:@-]+$`).MatchString(value) || value[0] == '-' {
			return errors.New("migration_endpoint_invalid")
		}
	}
	if o.NewIP != "" && net.ParseIP(o.NewIP) == nil {
		return errors.New("migration_bridge_address_invalid")
	}
	if o.Phase == "freeze" && (o.Confirm != "FREEZE" || o.AgeIdentity == "") {
		return errors.New("migration_explicit_freeze_and_offline_key_required")
	}
	if o.Phase == "activate" && (o.Confirm != "ACTIVATE" || !o.NetworkReady || o.ProbeURL == "" || net.ParseIP(o.ExpectedIP) == nil) {
		return errors.New("migration_explicit_cutover_and_payload_required")
	}
	if o.Phase == "verify" && (o.ProbeURL == "" || net.ParseIP(o.ExpectedIP) == nil) {
		return errors.New("migration_payload_required")
	}
	if o.ProbeURL != "" {
		u, err := url.Parse(o.ProbeURL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
			return errors.New("migration_https_payload_endpoint_required")
		}
	}
	if o.Phase == "rollback" && o.Confirm != "ROLLBACK" {
		return errors.New("migration_explicit_rollback_required")
	}
	return nil
}
func validateMigrationMachines(source, target migrationMachine) error {
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(source.MachineID) || !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(target.MachineID) || source.MachineID == target.MachineID {
		return errors.New("migration_distinct_machines_required")
	}
	if (source.OS != "ubuntu" && source.OS != "debian") || target.OS != "ubuntu" || target.OSVersion != "24.04" {
		return errors.New("migration_supported_linux_required")
	}
	if source.Architecture != "x86_64" || target.Architecture != source.Architecture {
		return errors.New("migration_same_supported_architecture_required")
	}
	if !regexp.MustCompile(`^postgresql@16-[A-Za-z0-9_-]+\.service$`).MatchString(source.PGUnit) {
		return errors.New("migration_single_postgresql_cluster_required")
	}
	if source.PGMajor != 16 || (target.PGMajor != 0 && target.PGMajor != source.PGMajor) {
		return errors.New("migration_postgresql16_required")
	}
	if target.PythonABI != "3.12" {
		return errors.New("migration_offline_controller_python312_required")
	}
	if source.CPUCount <= 0 || target.CPUCount < source.CPUCount {
		return errors.New("migration_cpu_insufficient")
	}
	if source.DatabaseBytes < 0 || source.StateBytes < 0 {
		return errors.New("migration_invalid_size_evidence")
	}
	if source.MemoryBytes <= 0 || target.MemoryBytes < source.MemoryBytes {
		return errors.New("migration_memory_insufficient")
	}
	if source.DatabaseBytes > (1<<63-1)/8 || source.StateBytes > (1<<63-1)/8 {
		return errors.New("migration_invalid_size_evidence")
	}
	needed := source.DatabaseBytes*4 + source.StateBytes*3 + 512*1024*1024
	if target.FreeBytes < needed {
		return errors.New("migration_disk_insufficient")
	}
	return nil
}
func migrationInventory(o migrationOptions) map[string]any {
	host := func(name, user, identity, role string) map[string]any {
		result := map[string]any{"ansible_host": name, "ansible_user": user, "ansible_become": user != "root", "ansible_ssh_private_key_file": identity, "ansible_ssh_args": "-F /dev/null -o ControlMaster=no -o ControlPath=none", "ansible_ssh_common_args": "-o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o UpdateHostKeys=no -o UserKnownHostsFile=" + shellQuote(o.Pins), "ultra_migration_host_role": role}
		if localLifecycleBridge(&installplan.InstallPlan{Bridge: installplan.BridgeConfig{SSHHost: name}}) {
			result["ansible_connection"] = "local"
			result["ansible_become"] = false
		}
		return result
	}
	target := host(o.TargetHost, o.TargetUser, o.TargetIdentity, "target")
	return map[string]any{"all": map[string]any{"children": map[string]any{"migration_sources": map[string]any{"hosts": map[string]any{"source": host(o.SourceHost, o.SourceUser, o.SourceIdentity, "source")}}, "migration_targets": map[string]any{"hosts": map[string]any{"target": target}}, "restore_targets": map[string]any{"hosts": map[string]any{"target": target}}}}}
}
func saveMigrationState(path string, state migrationState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	return replaceUpgradeMetadata(path, data)
}

func prepareMigrationGeneration(ctx context.Context, o migrationOptions, p *installplan.InstallPlan, directory string, state migrationState) error {
	if o.NewIP == "" {
		o.NewIP = p.Bridge.Address
	}
	if net.ParseIP(o.NewIP) == nil || net.ParseIP(state.Source.BridgeAddress) == nil {
		return errors.New("migration_literal_bridge_addresses_required")
	}
	if o.Provider == "" && p.Automation != nil {
		o.Provider = p.Automation.BridgeProvider
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`).MatchString(o.Provider) {
		return errors.New("migration_explicit_new_provider_required")
	}
	if o.NewPublicHost == "" {
		o.NewPublicHost = state.Source.PublicHost
	}
	var capture struct {
		BackupName   string `json:"backup_name"`
		ArtifactName string `json:"artifact_name"`
		BackupSHA    string `json:"backup_sha256"`
		ArtifactSHA  string `json:"artifact_sha256"`
	}
	raw, err := os.ReadFile(filepath.Join(directory, "capture.json"))
	if err != nil || json.Unmarshal(raw, &capture) != nil {
		return errors.New("migration_capture_invalid")
	}
	for kind, item := range map[string]struct{ Name, SHA string }{"backup": {capture.BackupName, capture.BackupSHA}, "artifact": {capture.ArtifactName, capture.ArtifactSHA}} {
		if !regexp.MustCompile(`^[A-Za-z0-9_.-]+\.age$`).MatchString(item.Name) {
			return errors.New("migration_ciphertext_name_invalid")
		}
		if err = copyMigrationCipher(filepath.Join(directory, kind+".age"), filepath.Join(directory, item.Name), item.SHA); err != nil {
			return err
		}
	}
	runtime := filepath.Join(directory, "runtime")
	if err = os.MkdirAll(runtime, 0700); err != nil {
		return err
	}
	entries, err := recoveryassets.Scripts.ReadDir(".")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := recoveryassets.Scripts.ReadFile(entry.Name())
		if err != nil {
			return err
		}
		if err = writeUpgradeInput(filepath.Join(runtime, entry.Name()), data); err != nil {
			return err
		}
	}
	helper, err := ansibleassets.Bundle.ReadFile("roles/bridge_migration/files/prepare_data.py")
	if err != nil {
		return err
	}
	if err = writeUpgradeInput(filepath.Join(directory, "prepare_data.py"), helper); err != nil {
		return err
	}
	identity := map[string]any{"source_machine_id": state.Source.MachineID, "target_machine_id": state.Target.MachineID, "source_ssh_endpoint": o.SourceUser + "@" + o.SourceHost, "target_ssh_endpoint": o.TargetUser + "@" + o.TargetHost}
	fence := map[string]any{"source": "bridge", "source_address": state.Source.BridgeAddress, "target_host": o.TargetUser + "@" + o.TargetHost, "confirmed_offline": true, "confirmed_at": time.Now().Unix(), "source_machine_id": state.Source.MachineID, "target_machine_id": state.Target.MachineID, "source_ssh_endpoint": o.SourceUser + "@" + o.SourceHost, "target_ssh_endpoint": o.TargetUser + "@" + o.TargetHost}
	fence["migration_identity"] = identity
	raw, _ = json.Marshal(fence)
	if err = replaceUpgradeMetadata(filepath.Join(directory, "fence.json"), raw); err != nil {
		return err
	}
	configuration := map[string]any{"format": 1, "source": "bridge", "old_bridge_address": state.Source.BridgeAddress, "new_bridge_address": o.NewIP, "new_bridge_provider": o.Provider, "public_host": o.NewPublicHost, "subscription_domain": state.Source.SubscriptionDomain, "ingress_mode": "direct", "bundle": filepath.Join(directory, capture.BackupName), "identity": o.AgeIdentity, "fence_file": filepath.Join(directory, "fence.json"), "state_dir": filepath.Join(directory, "data-state"), "target": map[string]any{"host": o.TargetUser + "@" + o.TargetHost, "identity": o.TargetIdentity, "known_hosts": o.Pins}}
	if state.Source.ForwardHost != "" {
		configuration["ingress_mode"] = "forward"
		configuration["ingress"] = map[string]any{"host": "root@" + state.Source.ForwardHost, "identity": o.SourceIdentity, "known_hosts": o.Pins}
	}
	configuration["migration_identity"] = identity
	raw, _ = json.Marshal(configuration)
	if err = writeUpgradeInput(filepath.Join(directory, "restore-config.json"), raw); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, o.Python, filepath.Join(directory, "prepare_data.py"), directory)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	if command.Run() != nil {
		return errors.New("migration_generation_proof_failed")
	}
	return nil
}
func migrationRestorePhases(ctx context.Context, o migrationOptions, directory string, base map[string]any, phases []string) error {
	var prepared struct {
		Plan    map[string]any `json:"plan"`
		Archive string         `json:"archive"`
	}
	raw, err := os.ReadFile(filepath.Join(directory, "restore-plan.json"))
	if err != nil || json.Unmarshal(raw, &prepared) != nil {
		return errors.New("migration_restore_plan_unavailable")
	}
	variables := map[string]any{}
	for key, value := range base {
		variables[key] = value
	}
	variables["ultra_restore_id"] = prepared.Plan["restore_id"]
	variables["ultra_restore_directory"] = "/var/lib/ultra-restore/" + fmt.Sprint(prepared.Plan["restore_id"])
	prepared.Plan["ingress_confirmed"] = o.NetworkReady
	variables["ultra_restore_plan"] = prepared.Plan
	variables["ultra_restore_script_directory"] = filepath.Join(directory, "runtime")
	variables["ultra_restore_stage_archive"] = prepared.Archive
	variables["ultra_restore_app_units"] = []string{"ultra-relay.service", "ultra-bot.service"}
	variables["ultra_restore_automation_units"] = base["ultra_migration_automation_units"]
	for _, phase := range phases {
		if err = migrationRefreshFence(ctx, o, directory, variables, prepared.Plan); err != nil {
			return err
		}
		variables["ultra_restore_plan"] = prepared.Plan
		variables["ultra_restore_phase"] = phase
		attempt, err := os.MkdirTemp(directory, "restore-"+phase+"-")
		if err != nil {
			return err
		}
		_ = os.Remove(attempt)
		receipt, runErr := deployansible.RunLocal(ctx, "restore", migrationInventory(o), variables, attempt, o.Python, o.Ansible)
		if runErr != nil {
			return runErr
		}
		if phase == "peer_reseed" {
			raw, _ := json.Marshal(receipt.Result.Values["reseed_nodes"])
			if err = replaceUpgradeMetadata(filepath.Join(directory, "migration-peers.json"), raw); err != nil {
				return err
			}
			if err = migrationReseedPeers(ctx, o, directory, variables, receipt.Result.Values["reseed_nodes"]); err != nil {
				return err
			}
		}
	}
	return nil
}
func migrationPayloadProbe(ctx context.Context, o migrationOptions, directory string, base map[string]any) error {
	variables := map[string]any{}
	for key, value := range base {
		variables[key] = value
	}
	if err := migrationRefreshFence(ctx, o, directory, variables, nil); err != nil {
		return err
	}
	var prepared struct {
		Plan map[string]any `json:"plan"`
	}
	raw, err := os.ReadFile(filepath.Join(directory, "restore-plan.json"))
	if err != nil || json.Unmarshal(raw, &prepared) != nil {
		return errors.New("migration_restore_plan_unavailable")
	}
	variables["ultra_migration_target_address"] = prepared.Plan["new_bridge_address"]
	variables["ultra_migration_probe_url"] = o.ProbeURL
	variables["ultra_migration_expected_ip"] = o.ExpectedIP
	attempt, err := os.MkdirTemp(directory, "payload-")
	if err != nil {
		return err
	}
	_ = os.Remove(attempt)
	_, err = deployansible.RunLocal(ctx, "bridge-migrate-probe", migrationInventory(o), variables, attempt, o.Python, o.Ansible)
	return err
}

func migrationRefreshFence(ctx context.Context, o migrationOptions, directory string, variables, plan map[string]any) error {
	attempt, err := os.MkdirTemp(directory, "fence-")
	if err != nil {
		return err
	}
	_ = os.Remove(attempt)
	if _, err = deployansible.RunLocal(ctx, "bridge-migrate-fence", migrationInventory(o), variables, attempt, o.Python, o.Ansible); err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(directory, "fence.json"))
	if err != nil {
		return err
	}
	var fence map[string]any
	if json.Unmarshal(raw, &fence) != nil {
		return errors.New("migration_fence_invalid")
	}
	fence["confirmed_at"] = time.Now().Unix()
	raw, _ = json.Marshal(fence)
	if err = replaceUpgradeMetadata(filepath.Join(directory, "fence.json"), raw); err != nil {
		return err
	}
	if plan != nil {
		plan["fence"] = fence
	}
	return nil
}

func copyMigrationCipher(source, destination, expected string) error {
	if !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(expected) {
		return errors.New("migration_ciphertext_hash_invalid")
	}
	validate := func(path string) (string, error) {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return "", errors.New("migration_ciphertext_invalid")
		}
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer file.Close() //nolint:errcheck
		hash := sha256.New()
		if _, err = io.Copy(hash, file); err != nil {
			return "", err
		}
		return hex.EncodeToString(hash.Sum(nil)), nil
	}
	actual, err := validate(source)
	if err != nil {
		return err
	}
	if actual != expected {
		return errors.New("migration_ciphertext_checksum_mismatch")
	}
	if _, err = os.Lstat(destination); err == nil {
		actual, err = validate(destination)
		if err != nil || actual != expected {
			return errors.New("migration_immutable_ciphertext_changed")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close() //nolint:errcheck
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	syncErr := output.Sync()
	closeErr := output.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || hex.EncodeToString(hash.Sum(nil)) != expected {
		_ = os.Remove(destination)
		return errors.New("migration_ciphertext_copy_failed")
	}
	return syncUpgradeDirectory(filepath.Dir(destination))
}

// No source restart is permitted without a current acknowledgement that the
// target cannot accept database writes. This recovery runs only before cutover.
func recoverMigrationFreeze(cause error, state *migrationState, statePath string, variables map[string]any, call func(string) error) error {
	if err := call("stop-target"); err != nil {
		return errors.Join(cause, errors.New("migration_source_kept_fenced_target_stop_unconfirmed"))
	}
	variables["ultra_migration_confirm"] = "ROLLBACK"
	variables["ultra_migration_network_restored"] = true // freeze precedes the explicit network-ready activation.
	if err := call("rollback-source"); err != nil {
		return errors.Join(cause, errors.New("migration_source_restart_failed"))
	}
	state.Phase = "rolled_back"
	return errors.Join(cause, saveMigrationState(statePath, *state))
}

func migrationTargetPlan(p *installplan.InstallPlan, o migrationOptions) *installplan.InstallPlan {
	return migrationEndpointPlan(p, o, true)
}
func migrationLifecycleInventory(o migrationOptions, target bool) map[string]any {
	inventory := migrationInventory(o)
	all := inventory["all"].(map[string]any)
	children := all["children"].(map[string]any)
	group, alias := "migration_sources", "source"
	if target {
		group, alias = "migration_targets", "target"
	}
	hosts := children[group].(map[string]any)["hosts"].(map[string]any)
	return map[string]any{"all": map[string]any{"children": map[string]any{"bridges": map[string]any{"hosts": map[string]any{"bridge": hosts[alias]}}}}}
}
func migrationReady(ctx context.Context, o migrationOptions, directory string, variables map[string]any) error {
	deadline := time.NewTimer(15 * time.Minute)
	defer deadline.Stop()
	for {
		err := migrationRestorePhases(ctx, o, directory, variables, []string{"ready"})
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("migration_passive_readiness_timeout")
		case <-time.After(5 * time.Second):
		}
	}
}
func migrationReseedPeers(ctx context.Context, o migrationOptions, directory string, variables map[string]any, nodes any) error {
	raw, err := json.Marshal(nodes)
	if err != nil {
		return err
	}
	projection, err := os.MkdirTemp(directory, "peers-")
	if err != nil {
		return err
	}
	if err = writeUpgradeInput(filepath.Join(projection, "nodes.json"), raw); err != nil {
		return err
	}
	helper, err := ansibleassets.Bundle.ReadFile("roles/bridge_migration/files/project_peers.py")
	if err != nil {
		return err
	}
	if err = writeUpgradeInput(filepath.Join(projection, "project.py"), helper); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, o.Python, filepath.Join(projection, "project.py"), directory, projection)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	if command.Run() != nil {
		return errors.New("migration_peer_projection_failed")
	}
	var inputs []struct {
		Inventory map[string]any `json:"inventory"`
		Variables map[string]any `json:"variables"`
	}
	raw, err = os.ReadFile(filepath.Join(projection, "inputs.json"))
	if err != nil || json.Unmarshal(raw, &inputs) != nil {
		return errors.New("migration_peer_projection_invalid")
	}
	for index, input := range inputs {
		fence, fenceErr := migrationPeerFence(ctx, o, directory, variables)
		if fenceErr != nil {
			return fenceErr
		}
		peerPlan, ok := input.Variables["ultra_peer_plan"].(map[string]any)
		if !ok {
			return errors.New("migration_peer_plan_invalid")
		}
		peerPlan["fence"] = fence
		if identity, ok := fence["migration_identity"]; ok {
			peerPlan["migration_identity"] = identity
		}
		input.Variables["ultra_lock_directory"] = variables["ultra_lock_directory"]
		if _, err = deployansible.RunLocal(ctx, "restore-peer", input.Inventory, input.Variables, filepath.Join(projection, fmt.Sprintf("peer-%d", index)), o.Python, o.Ansible); err != nil {
			return err
		}
	}
	return nil
}

func migrationIngress(ctx context.Context, o migrationOptions, directory string, variables map[string]any) error {
	var prepared struct {
		Plan map[string]any `json:"plan"`
	}
	raw, err := os.ReadFile(filepath.Join(directory, "restore-plan.json"))
	if err != nil || json.Unmarshal(raw, &prepared) != nil {
		return errors.New("migration_restore_plan_unavailable")
	}
	if prepared.Plan["ingress_mode"] == "forward" {
		var state migrationState
		raw, err = os.ReadFile(filepath.Join(directory, "migration.json"))
		if err != nil || json.Unmarshal(raw, &state) != nil {
			return errors.New("migration_receipt_invalid")
		}
		var nodes []map[string]any
		raw, err = os.ReadFile(filepath.Join(directory, "migration-peers.json"))
		if err != nil || json.Unmarshal(raw, &nodes) != nil {
			return errors.New("migration_peer_topology_unavailable")
		}
		var forward []map[string]any
		for _, node := range nodes {
			if node["address"] == state.Source.ForwardHost {
				plan := map[string]any{}
				for key, value := range prepared.Plan {
					plan[key] = value
				}
				plan["action"] = "forward"
				node["plan"] = plan
				forward = append(forward, node)
			}
		}
		if len(forward) != 1 {
			return errors.New("migration_unique_owned_forwarder_required")
		}
		if err = migrationRefreshFence(ctx, o, directory, variables, prepared.Plan); err != nil {
			return err
		}
		forward[0]["plan"].(map[string]any)["fence"] = prepared.Plan["fence"]
		if err = migrationReseedPeers(ctx, o, directory, variables, forward); err != nil {
			return err
		}
	}
	if err = migrationRestorePhases(ctx, o, directory, variables, []string{"ingress"}); err != nil {
		return err
	}
	domain, ok := prepared.Plan["subscription_domain"].(string)
	if !ok {
		return errors.New("migration_public_subscription_unavailable")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/healthz", nil)
	if err != nil {
		return errors.New("migration_public_subscription_unavailable")
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("migration_public_subscription_unavailable")
	}
	defer response.Body.Close() //nolint:errcheck
	if response.StatusCode != http.StatusOK {
		return errors.New("migration_public_subscription_unavailable")
	}
	return nil
}

func activateMigrationServices(restore func(string) error, payload func() error, stopTarget func() error) error {
	for _, phase := range []string{"peer_reseed", "activate", "payload", "migration-bot"} {
		var err error
		if phase == "payload" {
			err = payload()
		} else {
			err = restore(phase)
		}
		if err != nil {
			if stopErr := stopTarget(); stopErr != nil {
				return errors.Join(err, errors.New("migration_target_stop_unconfirmed"))
			}
			return err
		}
	}
	return nil
}

func migrationPeerFence(ctx context.Context, o migrationOptions, directory string, variables map[string]any) (map[string]any, error) {
	if reverse, ok := variables["ultra_migration_reverse_fence"].(map[string]any); ok {
		identity := reverse["migration_identity"].(map[string]any)
		swapped := o
		swapped.SourceHost = o.TargetHost
		swapped.TargetHost = o.SourceHost
		swapped.SourceUser = o.TargetUser
		swapped.TargetUser = o.SourceUser
		swapped.SourceIdentity = o.TargetIdentity
		swapped.TargetIdentity = o.SourceIdentity
		inputs := map[string]any{"ultra_lock_directory": variables["ultra_lock_directory"], "ultra_migration_source_machine_id": identity["source_machine_id"], "ultra_migration_target_machine_id": identity["target_machine_id"]}
		attempt, err := os.MkdirTemp(directory, "reverse-fence-")
		if err != nil {
			return nil, err
		}
		_ = os.Remove(attempt)
		if _, err = deployansible.RunLocal(ctx, "bridge-migrate-fence", migrationInventory(swapped), inputs, attempt, o.Python, o.Ansible); err != nil {
			return nil, err
		}
		reverse["confirmed_at"] = time.Now().Unix()
		return reverse, nil
	}
	if err := migrationRefreshFence(ctx, o, directory, variables, nil); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join(directory, "fence.json"))
	if err != nil {
		return nil, err
	}
	var fence map[string]any
	if json.Unmarshal(raw, &fence) != nil {
		return nil, errors.New("migration_fence_invalid")
	}
	return fence, nil
}
func migrationReverseReplicas(ctx context.Context, o migrationOptions, directory string, state migrationState, variables map[string]any) error {
	var prepared struct {
		Plan map[string]any `json:"plan"`
	}
	raw, err := os.ReadFile(filepath.Join(directory, "restore-plan.json"))
	if err != nil || json.Unmarshal(raw, &prepared) != nil {
		return errors.New("migration_reverse_plan_unavailable")
	}
	oldTarget, ok := prepared.Plan["new_bridge_address"].(string)
	if !ok {
		return errors.New("migration_reverse_plan_invalid")
	}
	identity := map[string]any{"source_machine_id": state.Target.MachineID, "target_machine_id": state.Source.MachineID, "source_ssh_endpoint": o.TargetUser + "@" + o.TargetHost, "target_ssh_endpoint": o.SourceUser + "@" + o.SourceHost}
	fence := map[string]any{"source": "bridge", "source_address": oldTarget, "target_host": o.SourceUser + "@" + o.SourceHost, "confirmed_offline": true, "confirmed_at": time.Now().Unix(), "migration_identity": identity}
	inputs := map[string]any{}
	for key, value := range variables {
		inputs[key] = value
	}
	inputs["ultra_migration_reverse_fence"] = fence
	fresh, err := migrationPeerFence(ctx, o, directory, inputs)
	if err != nil {
		return err
	}
	plan := map[string]any{"restore_id": prepared.Plan["restore_id"], "old_bridge_address": oldTarget, "new_bridge_address": state.Source.BridgeAddress, "target_host": o.SourceUser + "@" + o.SourceHost, "fence": fresh, "migration_identity": identity}
	inputs["ultra_migration_reverse_plan"] = plan
	inputs["ultra_migration_runtime_directory"] = filepath.Join(directory, "runtime")
	attempt, err := os.MkdirTemp(directory, "reverse-plan-")
	if err != nil {
		return err
	}
	_ = os.Remove(attempt)
	receipt, err := deployansible.RunLocal(ctx, "bridge-migrate-rollback-peers", migrationInventory(o), inputs, attempt, o.Python, o.Ansible)
	if err != nil {
		return err
	}
	if err = migrationReseedPeers(ctx, o, directory, inputs, receipt.Result.Values["nodes"]); err != nil {
		return err
	}
	if state.Source.ForwardHost != "" {
		var nodes []map[string]any
		raw, _ = json.Marshal(receipt.Result.Values["nodes"])
		if json.Unmarshal(raw, &nodes) != nil {
			return errors.New("migration_reverse_forwarder_invalid")
		}
		var forward []map[string]any
		for _, node := range nodes {
			if node["address"] == state.Source.ForwardHost {
				forwardPlan := map[string]any{}
				for key, value := range plan {
					forwardPlan[key] = value
				}
				forwardPlan["action"] = "forward"
				forwardPlan["subscription_domain"] = state.Source.SubscriptionDomain
				node["plan"] = forwardPlan
				forward = append(forward, node)
			}
		}
		if len(forward) != 1 {
			return errors.New("migration_unique_owned_forwarder_required")
		}
		if err = migrationReseedPeers(ctx, o, directory, inputs, forward); err != nil {
			return err
		}
	}
	return nil
}

func migrationEndpointPlan(p *installplan.InstallPlan, o migrationOptions, target bool) *installplan.InstallPlan {
	clone := *p
	clone.Bridge = p.Bridge
	clone.Bridge.SSHHost = o.SourceHost
	if target {
		clone.Bridge.SSHHost = o.TargetHost
	}
	return &clone
}
