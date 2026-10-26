package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"regexp"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type replacementExecutionScope struct {
	primary replacementPrimary
	files   map[string]string
}

func (scope *replacementExecutionScope) verifyPrimary(primary replacementPrimary) error {
	if scope.primary.SystemIdentifier == "" || scope.primary.SystemIdentifier != primary.SystemIdentifier ||
		scope.primary.Database != primary.Database ||
		scope.primary.DatabaseOID == 0 ||
		scope.primary.DatabaseOID != primary.DatabaseOID {
		return errors.New("replacement_failed_execution_primary_identity_changed")
	}
	return nil
}
func (scope *replacementExecutionScope) unchanged() error {
	for path, hash := range scope.files {
		raw, err := readRebuildInput(path, true)
		if err != nil || digestSHA256(raw) != hash {
			return errors.New("replacement_failed_execution_scope_changed")
		}
	}
	return nil
}

// The original replacement is derived from the exact fenced job, never from a
// latest-directory search. Only canonical fresh-bootstrap workspaces qualify.
func replacementExecutionState(directory string) (string, error) {
	attempt := filepath.Dir(directory)
	plan := filepath.Dir(attempt)
	bootstrap := filepath.Dir(plan)
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		!regexp.MustCompile(`^attempt-[0-9]+$`).MatchString(filepath.Base(attempt)) ||
		!regexp.MustCompile(`^bootstrap-[a-f0-9]{64}$`).MatchString(filepath.Base(plan)) || filepath.Base(bootstrap) != "bootstrap" {
		return "", errors.New("replacement_failed_execution_workspace_not_canonical")
	}
	return filepath.Dir(bootstrap), nil
}

func validateReplacementExecutionScope(
	fence deployansible.ExecutionFence,
	current *installplan.InstallPlan,
	plans []*installplan.InstallPlan,
) (*replacementExecutionScope, error) {
	switch fence.Operation {
	case "prepare-controller",
		"bootstrap",
		"bootstrap-postgres",
		"bootstrap-exit",
		"bootstrap-bridge",
		"bootstrap-automation",
		"configure-bot",
		"lifecycle",
		"ingress":
	default:
		return nil, errors.New("replacement_failed_execution_operation_not_supported")
	}
	oldState, err := replacementExecutionState(fence.JobDirectory)
	if err != nil {
		return nil, err
	}
	scope := &replacementExecutionScope{files: map[string]string{}}
	read := func(path string, target any) error {
		raw, err := readRebuildInput(path, true)
		if err != nil || retainedReconcileUniqueJSON(raw) != nil || json.Unmarshal(raw, target) != nil {
			return errors.New("replacement_failed_execution_scope_unavailable")
		}
		scope.files[path] = digestSHA256(raw)
		return nil
	}
	var request struct {
		Inventory struct {
			All struct {
				Vars     map[string]any `json:"vars"`
				Hosts    map[string]any `json:"hosts"`
				Children map[string]struct {
					Vars     map[string]any            `json:"vars"`
					Children map[string]any            `json:"children"`
					Hosts    map[string]map[string]any `json:"hosts"`
				} `json:"children"`
			} `json:"all"`
		} `json:"inventory"`
	}
	requestPath := filepath.Join(fence.JobDirectory, "request.json")
	if err = read(requestPath, &request); err != nil {
		return nil, err
	}
	if scope.files[requestPath] != fence.RequestSHA256 {
		return nil, errors.New("replacement_failed_execution_request_changed")
	}
	if err = read(filepath.Join(oldState, "primary-before.json"), &scope.primary); err != nil {
		return nil, err
	}
	var originalTargets []replacementTarget
	if err = read(filepath.Join(oldState, "targets.json"), &originalTargets); err != nil {
		return nil, err
	}
	authorized := map[string]map[string]bool{}
	primaryKeys := map[string]bool{}
	pinnedArgs := map[string]bool{}
	for _, plan := range plans {
		if plan.Database.PrimaryHost != current.Database.PrimaryHost || plan.Database.Name != current.Database.Name ||
			plan.Automation == nil {
			return nil, errors.New("replacement_failed_execution_primary_scope_mismatch")
		}
		targets, err := replacementTargets(plan)
		if err != nil {
			return nil, err
		}
		for _, target := range targets {
			if authorized[target.Address] == nil {
				authorized[target.Address] = map[string]bool{}
			}
			authorized[target.Address][target.Identity] = true
		}
		key := plan.Database.SSHIdentity
		if key == "" {
			key = plan.SSH.Identity
		}
		primaryKeys[key] = true
		pinnedArgs["-F /dev/null -o ControlMaster=no -o ControlPath=none -o UpdateHostKeys=no -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="+shellQuote(plan.Automation.KnownHostsFile)] = true
	}
	oldTargets := map[string]map[string]bool{}
	for _, target := range originalTargets {
		if !authorized[target.Address][target.Identity] || target.Address == current.Database.PrimaryHost {
			return nil, errors.New("replacement_failed_execution_target_not_retained")
		}
		if oldTargets[target.Address] == nil {
			oldTargets[target.Address] = map[string]bool{}
		}
		oldTargets[target.Address][target.Identity] = true
	}
	common := request.Inventory.All.Vars
	if len(request.Inventory.All.Hosts) != 0 || len(request.Inventory.All.Children) != 3 || common["ansible_user"] != "root" ||
		!pinnedArgs[stringValue(common["ansible_ssh_common_args"])] ||
		common["ultra_db_tunnel_host"] != current.Database.PrimaryHost {
		return nil, errors.New("replacement_failed_execution_transport_scope_mismatch")
	}
	if value, ok := common["ansible_connection"]; ok && value != "ssh" {
		return nil, errors.New("replacement_failed_execution_local_transport_forbidden")
	}
	seen := map[string]bool{}
	for _, groupName := range []string{"bridge", "exits", "databases"} {
		group, ok := request.Inventory.All.Children[groupName]
		if !ok || len(group.Vars) != 0 || len(group.Children) != 0 || len(group.Hosts) == 0 ||
			(groupName != "exits" && len(group.Hosts) != 1) {
			return nil, errors.New("replacement_failed_execution_inventory_scope_invalid")
		}
		for _, host := range group.Hosts {
			address := stringValue(host["ansible_host"])
			identity := stringValue(host["ansible_ssh_private_key_file"])
			if identity == "" {
				identity = stringValue(common["ansible_ssh_private_key_file"])
			}
			user, ok := host["ansible_user"]
			if !ok {
				user = common["ansible_user"]
			}
			args, ok := host["ansible_ssh_common_args"]
			if !ok {
				args = common["ansible_ssh_common_args"]
			}
			if address == "" || seen[address] || user != "root" || !pinnedArgs[stringValue(args)] {
				return nil, errors.New("replacement_failed_execution_host_scope_invalid")
			}
			if value, ok := host["ansible_connection"]; ok && value != "ssh" {
				return nil, errors.New("replacement_failed_execution_local_transport_forbidden")
			}
			seen[address] = true
			if groupName == "databases" {
				if address != current.Database.PrimaryHost || !primaryKeys[identity] {
					return nil, errors.New("replacement_failed_execution_primary_scope_mismatch")
				}
			} else if address == current.Database.PrimaryHost || !oldTargets[address][identity] || !authorized[address][identity] {
				return nil, errors.New("replacement_failed_execution_target_not_retained")
			}
		}
	}
	// The immutable source must describe the same dedicated application database.
	if scope.primary.Database != current.Database.Name {
		return nil, errors.New("replacement_failed_execution_primary_scope_mismatch")
	}
	return scope, nil
}

func admitReplacementFailedExecution(
	fence deployansible.ExecutionFence,
	scope *replacementExecutionScope,
	before replacementPrimary,
	steps replacementSteps,
) func(context.Context, func() error) error {
	return admitReplacementFailedExecutionWithProof(fence, scope, before, steps, deployansible.ProveFailedExecutionQuiescent)
}

// Only the local observation is injected in tests. Retirement always uses the
// real exact-generation API, with its admission lock and immutable checks.
func admitReplacementFailedExecutionWithProof(
	fence deployansible.ExecutionFence,
	scope *replacementExecutionScope,
	before replacementPrimary,
	steps replacementSteps,
	localProof func(deployansible.ExecutionFence) error,
) func(context.Context, func() error) error {
	return func(ctx context.Context, prepare func() error) error {
		var proofErr error
		err := deployansible.AbandonExecutionFence(fence, func(actual deployansible.ExecutionFence) error {
			prove := func() error {
				if actual != fence {
					return errors.New("replacement_failed_execution_generation_changed")
				}
				if err := scope.unchanged(); err != nil {
					return err
				}
				if err := localProof(actual); err != nil {
					return fmt.Errorf("replacement_failed_execution_still_active: %w", err)
				}
				if err := prepare(); err != nil {
					return err
				}
				observed, err := steps.Observe(ctx)
				if err != nil {
					return err
				}
				if !reflect.DeepEqual(before, observed) {
					return errors.New("replacement_primary_schema_or_topology_changed")
				}
				if err = scope.verifyPrimary(observed); err != nil {
					return err
				}
				// Observe opened its own SSH session; the canonical census waits for its
				// complete tail to disappear before accepting primary quiescence again.
				if err = steps.PrimaryQuiescent(ctx); err != nil {
					return err
				}
				if err = localProof(actual); err != nil {
					return fmt.Errorf("replacement_failed_execution_still_active: %w", err)
				}
				return scope.unchanged()
			}
			proofErr = prove()
			return proofErr
		})
		if proofErr != nil {
			return proofErr
		}
		return err
	}
}

// A crashed parent has no execution receipt. Its durable reservation instead
// binds the exact immutable target and primary snapshots. The next fresh run
// must retain every old target and prove the same primary identity; it then
// fences and proves all remote targets afresh before cleanup.
func validateReplacementReservationScope(
	record deployansible.ReplacementReservation,
	current *installplan.InstallPlan,
	plans []*installplan.InstallPlan,
	before replacementPrimary,
) error {
	read := func(name, hash string, target any) error {
		raw, err := readRebuildInput(filepath.Join(record.Binding.Workspace, name), true)
		if err != nil || digestSHA256(raw) != hash || retainedReconcileUniqueJSON(raw) != nil || json.Unmarshal(raw, target) != nil {
			return errors.New("replacement_reservation_scope_changed")
		}
		return nil
	}
	var primary replacementPrimary
	if err := read("primary-before.json", record.Binding.PrimarySHA256, &primary); err != nil {
		return err
	}
	if err := (&replacementExecutionScope{primary: primary}).verifyPrimary(before); err != nil {
		return err
	}
	var targets []replacementTarget
	if err := read("targets.json", record.Binding.TargetsSHA256, &targets); err != nil {
		return err
	}
	authorized := map[replacementTarget]bool{}
	for _, plan := range plans {
		if plan.Database.PrimaryHost != current.Database.PrimaryHost || plan.Database.Name != current.Database.Name {
			return errors.New("replacement_reservation_primary_scope_mismatch")
		}
		retained, err := replacementTargets(plan)
		if err != nil {
			return err
		}
		for _, target := range retained {
			authorized[target] = true
		}
	}
	if len(targets) == 0 {
		return errors.New("replacement_reservation_targets_empty")
	}
	for _, target := range targets {
		if !authorized[target] {
			return errors.New("replacement_reservation_target_not_retained")
		}
	}
	return nil
}
