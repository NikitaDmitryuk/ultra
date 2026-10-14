package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func lifecycleID(directory string) string {
	h := sha256.Sum256([]byte(directory))
	h[6] = (h[6] & 15) | 64
	h[8] = (h[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// Execution mode is frozen once per plan; controller installation cannot turn
// an operator gateway into a local target in the middle of its leased operation.
func localLifecycleBridge(p *installplan.InstallPlan) bool {
	// Initial native adoption uses fixed Ansible lifecycle operations throughout
	// its frozen attempt, even after the broker has been installed.
	if p.BridgeNative {
		return false
	}
	target := p.Bridge.SSHHost + "|" + p.Bridge.Address
	if p.ControllerLocal != nil && p.ControllerLocalTarget == target {
		return *p.ControllerLocal
	}
	local := attestLocalLifecycleBridge(p)
	p.ControllerLocal = &local
	p.ControllerLocalTarget = target
	return local
}
func attestLocalLifecycleBridge(p *installplan.InstallPlan) bool {
	// Locality is physical identity, not availability. A stopped broker must
	// fail its authenticated transition instead of selecting SSH to ourselves.
	return localLifecycleMachineIdentity(p)
}
func localLifecycleMachineIdentity(p *installplan.InstallPlan) bool {
	if os.Geteuid() != 0 {
		return false
	}
	path := "/var/lib/ultra-ansible/deployment-identity.json"
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	machine, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return false
	}
	return validLocalLifecycleIdentity(p, info, raw, machine)
}
func validLocalLifecycleIdentity(p *installplan.InstallPlan, info os.FileInfo, raw, machine []byte) bool {
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return false
	}
	host := net.ParseIP(p.Bridge.SSHHost)
	address := net.ParseIP(p.Bridge.Address)
	if host == nil || host.IsLoopback() || address == nil || address.IsLoopback() || !host.Equal(address) {
		return false
	}
	var identity struct {
		Schema  int    `json:"schema_version"`
		Role    string `json:"role"`
		Machine string `json:"machine_sha256"`
		Address string `json:"address"`
	}
	if json.Unmarshal(raw, &identity) != nil || identity.Schema != 1 || identity.Role != "bridge" || net.ParseIP(identity.Address) == nil || !host.Equal(net.ParseIP(identity.Address)) {
		return false
	}
	machineText := strings.TrimSpace(string(machine))
	if len(machineText) != 32 {
		return false
	}
	return identity.Machine == fmt.Sprintf("%x", sha256.Sum256([]byte(machineText)))
}

// ansibleLifecycle binds every stage to a durable bridge reservation. This
// directory is the whole immutable attempt, not a per-stage work directory.
func ansibleLifecycle(ctx context.Context, p *installplan.InstallPlan, inventory map[string]any, directory, python, executable, phase string, drain bool) error {
	_, err := ansibleLifecycleTransition(ctx, p, inventory, directory, python, executable, phase, drain, false)
	return err
}

// ansibleLifecycleReserve returns only after the broker confirms this exact
// operation ID and phase. Callers may then safely install same-ID recovery
// before attempting any operation that can fail after reservation.
func ansibleLifecycleReserve(ctx context.Context, p *installplan.InstallPlan, inventory map[string]any, directory, python, executable, phase string) (deployansible.Receipt, error) {
	id := lifecycleID(directory)
	if localLifecycleBridge(p) {
		socket := os.Getenv("ULTRA_ANSIBLE_SOCKET")
		if socket == "" {
			socket = "/run/ultra-ansible/controller.sock"
		}
		if err := (deployansible.Client{Socket: socket}).LifecycleWithOperationLock(ctx, id, phase); err != nil {
			return deployansible.Receipt{}, err
		}
		return deployansible.Receipt{Result: deployansible.Result{Values: map[string]any{"verified": true, "reservation_id": id, "reservation_phase": phase}}}, nil
	}
	receipt, err := ansibleLifecycleTransition(ctx, p, inventory, directory, python, executable, phase, false, true)
	if err != nil {
		return deployansible.Receipt{}, err
	}
	values := receipt.Result.Values
	if values["verified"] != true || values["reservation_id"] != id || values["reservation_phase"] != phase {
		return deployansible.Receipt{}, errors.New("lifecycle_reservation_unverified")
	}
	return receipt, nil
}

func ansibleLifecycleTransition(ctx context.Context, p *installplan.InstallPlan, inventory map[string]any, directory, python, executable, phase string, drain, reserveOnly bool) (deployansible.Receipt, error) {
	id := lifecycleID(directory)
	if localLifecycleBridge(p) {
		if err := (deployansible.Client{Socket: lifecycleSocket()}).LifecycleWithOperationLock(ctx, id, phase); err != nil {
			return deployansible.Receipt{}, err
		}
		if phase == "applying" && !reserveOnly {
			if drain {
				if err := drainLocalLifecycle(ctx); err != nil {
					return deployansible.Receipt{}, err
				}
			} else if err := assertLocalRelayStopped(ctx); err != nil {
				return deployansible.Receipt{}, err
			}
		}
		return deployansible.Receipt{Result: deployansible.Result{Values: map[string]any{"verified": true, "reservation_id": id, "reservation_phase": phase}}}, nil
	}
	// A native remote root module performs the exact same fixed transition and
	// drain. For local bridge it is idempotent after the OFD handoff above.
	variables := map[string]any{"ultra_lifecycle_id": id, "ultra_lifecycle_phase": phase, "ultra_lifecycle_drain": drain, "ultra_lifecycle_reserve_only": reserveOnly}
	stage, err := os.MkdirTemp(directory, "lifecycle-"+phase+"-")
	if err != nil {
		return deployansible.Receipt{}, err
	}
	if err = os.Remove(stage); err != nil {
		return deployansible.Receipt{}, err
	}
	return deployansible.RunLocal(ctx, "lifecycle", inventory, variables, stage, python, executable)
}

func lifecycleSocket() string {
	if socket := os.Getenv("ULTRA_ANSIBLE_SOCKET"); socket != "" {
		return socket
	}
	return "/run/ultra-ansible/controller.sock"
}

func prepareBootstrapController(ctx context.Context, p *installplan.InstallPlan, inventory map[string]any, directory, architecture, python, executable string) (map[string]any, error) {
	if p.Automation == nil {
		return nil, fmt.Errorf("independent controller release required for fleet lifecycle")
	}
	a := p.Automation
	manifest, err := verifyAutomationRelease(a.ReleaseDir, a.Version)
	if err != nil {
		return nil, err
	}
	installer, err := upgradeAsset(manifest, "ultra-install-linux-"+architecture)
	if err != nil {
		return nil, err
	}
	runtime, err := upgradeAsset(manifest, "ultra-ansible-runtime-linux-"+architecture+".tar.gz")
	if err != nil {
		return nil, err
	}
	contract, err := recoveryassets.Scripts.ReadFile("recovery_status.py")
	if err != nil {
		return nil, err
	}
	variables := map[string]any{"ultra_controller_bridge_address": p.Bridge.Address, "ultra_adoption_schedules_file": filepath.Join(directory, "adoption-schedules.json"), "ultra_adoption_receipt_file": filepath.Join(directory, "adoption-maintenance.json"), "ultra_adoption_contract_content": string(contract), "ultra_adoption_contract_sha256": fmt.Sprintf("%x", sha256.Sum256(contract)), "ultra_lifecycle_id": lifecycleID(directory), "ultra_controller_directory": managedControllerDirectory(a.Version),
		"ultra_install_source": filepath.Join(a.ReleaseDir, installer.Name), "ultra_install_sha256": installer.SHA,
		"ultra_controller_runtime_archive": filepath.Join(a.ReleaseDir, runtime.Name), "ultra_controller_runtime_sha256": runtime.SHA}
	stage, err := os.MkdirTemp(directory, "controller-prepare-")
	if err != nil {
		return nil, err
	}
	if err = os.Remove(stage); err != nil {
		return nil, err
	}
	receipt, err := deployansible.RunLocal(ctx, "prepare-controller", inventory, variables, stage, python, executable)
	return receipt.Result.Values, err
}

func drainLocalLifecycle(ctx context.Context) error {
	raw, err := os.ReadFile("/etc/ultra-relay/spec.json")
	if err != nil {
		return errors.New("lifecycle_drain_failed")
	}
	var spec struct {
		Listen string `json:"admin_listen"`
	}
	if json.Unmarshal(raw, &spec) != nil {
		return errors.New("lifecycle_drain_failed")
	}
	host, _, err := net.SplitHostPort(spec.Listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("lifecycle_drain_failed")
	}
	values, err := installplan.ReadSecretsFile("/etc/ultra-relay/environment")
	if err != nil || values["ULTRA_RELAY_ADMIN_TOKEN"] == "" {
		return errors.New("lifecycle_drain_failed")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+spec.Listen+"/v1/deployment/drain", nil)
	if err != nil {
		return errors.New("lifecycle_drain_failed")
	}
	req.Header.Set("Authorization", "Bearer "+values["ULTRA_RELAY_ADMIN_TOKEN"])
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 20 * time.Second}
	response, err := client.Do(req)
	if err != nil {
		return errors.New("lifecycle_drain_failed")
	}
	defer response.Body.Close() //nolint:errcheck
	var result struct {
		Verified bool `json:"verified"`
	}
	if response.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&result) != nil || !result.Verified {
		return errors.New("lifecycle_drain_failed")
	}
	return nil
}

// prepareReservedBootstrap is a single pre-base transaction. Legacy service
// recovery runs before returning an error; os.Exit in the outer CLI cannot skip
// it. Once base mutation starts, recovery belongs to compatible release rollback.
func prepareReservedBootstrap(ctx context.Context, p *installplan.InstallPlan, inventory map[string]any, inspection map[string]bootstrapInspection, directory, stateRoot, python, executable string, formats ...string) (frozen map[string]any, result map[string]bootstrapInspection, returnErr error) {
	// A proven rollback reuses its original checkpoint and identities. Re-running
	// checkpoint capture would compare the emergency binary to a newer manifest.
	if _, err := os.Lstat(filepath.Join(directory, "inventory.frozen.json")); err == nil {
		original, _, err := bootstrapFinalizationInputs(directory)
		if err != nil {
			return nil, nil, err
		}
		generation, err := resumeBootstrapMutationGeneration(ctx, p, directory, original, python, executable)
		if err != nil {
			return nil, nil, err
		}
		if generation > 1 {
			cachedRaw, err := readBootstrapGenerationInput(filepath.Join(directory, "post-gate", "inspect", "receipt.json"))
			var cached map[string]any
			if err != nil || json.Unmarshal(cachedRaw, &cached) != nil || cached["state"] != "succeeded" {
				return nil, nil, errors.New("bootstrap_original_inspection_unavailable")
			}
			// Validate the original derived request before any re-reservation effect.
			_, previous, err := inspectBootstrap(ctx, p, filepath.Join(directory, "post-gate"), python, executable, stateRoot)
			if err != nil {
				return nil, nil, err
			}
			_, err = deployansible.RunLocalRetryFailed(ctx, "reserve-rolledback-bootstrap", original, map[string]any{"ultra_lifecycle_id": lifecycleID(directory), "ultra_lock_directory": stateRoot}, bootstrapMutationStage(directory, "reserve-rolledback", generation), python, executable)
			if err != nil {
				return nil, nil, err
			}
			return original, previous, nil
		}
	} else if !os.IsNotExist(err) {
		return nil, nil, err
	}
	supportsGate := false
	for _, capability := range inspection["bridge"].Capabilities {
		if capability == "lifecycle-gate-v1" {
			supportsGate = true
		}
	}
	defer func() {
		if returnErr == nil {
			return
		}
		if _, err := os.Lstat(filepath.Join(directory, "apply", "job.json")); err == nil {
			return
		}
		if _, err := os.Lstat(filepath.Join(directory, "bootstrap-postgres", "job.json")); err == nil {
			return
		}
		if _, err := os.Lstat(filepath.Join(directory, "adoption-maintenance.json")); err != nil {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
			defer cancel()
			if _, scheduleReceiptErr := os.Lstat(filepath.Join(directory, "adoption-schedules.json")); scheduleReceiptErr == nil {
				if scheduleErr := restoreAdoptionSchedules(cleanup, inventory, directory, python, executable); scheduleErr != nil {
					returnErr = errors.Join(returnErr, scheduleErr)
					return
				}
			}
			// Legacy capture may fail before installing the broker and gate.
			// An existing gate must release even if drain failed before schedules
			// were inspected and their receipt was written.
			if supportsGate {
				if gateErr := ansibleLifecycle(cleanup, p, inventory, directory, python, executable, "released", false); gateErr != nil {
					returnErr = errors.Join(returnErr, gateErr)
				}
			}
			return
		}
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		stage, err := os.MkdirTemp(directory, "resume-adoption-")
		if err == nil {
			err = os.Remove(stage)
		}
		if err == nil {
			_, err = deployansible.RunLocal(cleanup, "resume-adoption", inventory, map[string]any{"ultra_lifecycle_id": lifecycleID(directory)}, stage, python, executable)
		}
		if err != nil {
			returnErr = errors.Join(returnErr, errors.New("pre_base_previous_service_recovery_unconfirmed"))
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
	event := func(stage string) {
		if len(formats) > 0 {
			emitInstallEvent(formats[0], installplan.EventStep, "", stage, "")
		}
	}
	event("checking independent recovery and preparing the pinned controller")
	if supportsGate {
		if err := ansibleLifecycle(ctx, p, inventory, directory, python, executable, "applying", true); err != nil {
			return nil, nil, err
		}
	}
	values, err := prepareBootstrapController(ctx, p, inventory, directory, inspection["bridge"].Architecture, python, executable)
	if err != nil {
		return nil, nil, err
	}
	verified, _ := values["verified"].(bool)
	legacy, _ := values["legacy"].(bool)
	fresh, _ := values["fresh"].(bool)
	stopped, _ := values["stopped"].(bool)
	if !verified {
		return nil, nil, errors.New("prepared_controller_receipt_invalid")
	}
	event("reserving the fleet and draining existing control operations")
	if err = ansibleLifecycle(ctx, p, inventory, directory, python, executable, "applying", !legacy && !fresh && !stopped); err != nil {
		return nil, nil, err
	}
	event("recording the reserved topology and application state")
	inventory, inspection, err = inspectBootstrap(ctx, p, filepath.Join(directory, "post-gate"), python, executable, stateRoot)
	if err != nil {
		return nil, nil, err
	}
	frozen, err = freezeBootstrapInventory(p, inventory, inspection, directory)
	return frozen, inspection, err
}

// Only an already frozen, private attempt may skip a second application drain
// during rollback. The broker separately requires the same still-active UUID.
func ansibleResumeFrozenLifecycle(ctx context.Context, p *installplan.InstallPlan, inventory map[string]any, directory, python, executable string) error {
	frozen, _, err := bootstrapFinalizationInputs(directory)
	expected, marshalErr := json.Marshal(inventory)
	actual, frozenErr := json.Marshal(frozen)
	if err != nil || marshalErr != nil || frozenErr != nil || string(actual) != string(expected) {
		return errors.New("rollback_frozen_attempt_unavailable")
	}
	id := lifecycleID(directory)
	if localLifecycleBridge(p) {
		socket := os.Getenv("ULTRA_ANSIBLE_SOCKET")
		if socket == "" {
			socket = "/run/ultra-ansible/controller.sock"
		}
		return (deployansible.Client{Socket: socket}).ResumeLifecycleWithOperationLock(ctx, id)
	}
	stage, err := os.MkdirTemp(directory, "lifecycle-resume-")
	if err != nil {
		return err
	}
	if err = os.Remove(stage); err != nil {
		return err
	}
	_, err = deployansible.RunLocal(ctx, "lifecycle", inventory, map[string]any{"ultra_lifecycle_id": id, "ultra_lifecycle_phase": "applying", "ultra_lifecycle_drain": false, "ultra_lifecycle_resume": true}, stage, python, executable)
	return err
}

func restoreAdoptionSchedules(ctx context.Context, inventory map[string]any, directory, python, executable string) error {
	path := filepath.Join(directory, "adoption-schedules.json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 1024 {
		return errors.New("adoption_schedule_receipt_invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var schedules []string
	if json.Unmarshal(raw, &schedules) != nil || len(schedules) > 2 {
		return errors.New("adoption_schedule_receipt_invalid")
	}
	seen := map[string]bool{}
	for _, name := range schedules {
		if seen[name] || (name != "ultra-recovery-backup.timer" && name != "ultra-recovery-reconcile.timer") {
			return errors.New("adoption_schedule_receipt_invalid")
		}
		seen[name] = true
	}
	stage, err := os.MkdirTemp(directory, "resume-schedules-")
	if err != nil {
		return err
	}
	if err = os.Remove(stage); err != nil {
		return err
	}
	_, err = deployansible.RunLocal(ctx, "resume-schedules", inventory, map[string]any{"ultra_adoption_schedules": schedules}, stage, python, executable)
	return err
}

func assertLocalRelayStopped(ctx context.Context) error {
	command := exec.CommandContext(ctx, "/usr/bin/systemctl", "is-active", "ultra-relay.service")
	err := command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || (exit.ExitCode() != 3 && exit.ExitCode() != 4) {
		return errors.New("lifecycle_undrained_worker_running")
	}
	if exit.ExitCode() == 3 {
		out, err := exec.CommandContext(ctx, "/usr/bin/systemctl", "show", "-p", "MainPID", "--value", "ultra-relay.service").Output()
		if err != nil || strings.TrimSpace(string(out)) != "0" {
			return errors.New("lifecycle_undrained_worker_running")
		}
	}
	return nil
}
