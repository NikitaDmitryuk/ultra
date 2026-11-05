package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// These bindings come from the same read-only primary snapshot as Routes. They
// are deliberately separate from the destructive/static SSH inventory.
type replacementPingRoute struct {
	ID          string `json:"id"`
	Address     string `json:"address"`
	Port        int    `json:"port"`
	TunnelUUID  string `json:"tunnel_uuid"`
	Pin         string `json:"pin"`
	OperationID string `json:"operation_id"`
	InstanceID  string `json:"instance_id"`
	State       string `json:"state"`
	Retained    bool   `json:"retained,omitempty"`
	KnownHosts  string `json:"known_hosts,omitempty"`
}

type replacementPingRollout struct {
	Binding                  string                 `json:"binding"`
	BinarySHA256             string                 `json:"binary_sha256"`
	Nodes                    []replacementPingRoute `json:"nodes"`
	BotEnabled               bool                   `json:"bot_enabled"`
	Installer                string                 `json:"installer"`
	InstallerSHA256          string                 `json:"installer_sha256"`
	ControllerLayoutVerified bool                   `json:"controller_layout_verified"`
	ControllerArchitecture   string                 `json:"controller_architecture"`
}

func validateReplacementPingControllerAttestation(rollout replacementPingRollout) error {
	if !rollout.ControllerLayoutVerified || rollout.ControllerArchitecture != "linux-amd64" {
		return errors.New("replacement_exit_ping_bridge_architecture_unverified")
	}
	return nil
}

func stepsObserveReplacement(
	ctx context.Context,
	observe func(context.Context) (replacementPrimary, error),
	expected replacementPrimary,
) error {
	actual, err := observe(ctx)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, expected) {
		return errors.New("replacement_primary_schema_or_topology_changed")
	}
	return nil
}

func replacementPingRequested(p *installplan.InstallPlan) bool {
	return p.Features.HappExitPing != nil && *p.Features.HappExitPing
}

func resolveReplacementPingPolicy(p *installplan.InstallPlan, installedExit, installedPublication bool) error {
	if p.Features.HappExitPing == nil {
		if installedPublication {
			return errors.New("replacement_exit_ping_explicit_publication_policy_required")
		}
		return nil
	}
	if !*p.Features.HappExitPing {
		return nil
	}
	if p.Features.ExitPing == nil {
		value := installedExit
		p.Features.ExitPing = &value
	}
	if p.Features.HappProviderID == nil || *p.Features.HappProviderID == "" {
		return errors.New("replacement_exit_ping_explicit_provider_required")
	}
	return nil
}

func observeReplacementPingPolicy(ctx context.Context, p *installplan.InstallPlan) error {
	if p.Features.HappExitPing != nil && (!*p.Features.HappExitPing || (p.Features.ExitPing != nil && p.Features.HappProviderID != nil)) {
		return nil
	}
	raw, err := retainedRemote(ctx, p, p.Bridge.SSHHost, p.BridgeSSHIdentity(), false, replacementPingPolicyProgram, nil)
	if err != nil {
		return errors.New("replacement_exit_ping_existing_policy_unavailable")
	}
	var policy struct {
		ExitPing     bool `json:"exit_ping"`
		HappExitPing bool `json:"happ_exit_ping"`
	}
	if json.Unmarshal(raw, &policy) != nil {
		return errors.New("replacement_exit_ping_existing_policy_invalid")
	}
	return resolveReplacementPingPolicy(p, policy.ExitPing, policy.HappExitPing)
}

func planReplacementPing(
	p *installplan.InstallPlan,
	before replacementPrimary,
	binding, binarySHA string,
) (*replacementPingRollout, error) {
	if !replacementPingRequested(p) {
		return nil, nil
	}
	if p.Features.ExitPing == nil || !*p.Features.ExitPing || len(before.PingRoutes) == 0 {
		return nil, errors.New("replacement_exit_ping_coverage_required")
	}
	r := &replacementPingRollout{Binding: binding, BinarySHA256: binarySHA, BotEnabled: p.Bot.Enabled}
	seenID, seenAddress := map[string]bool{}, map[string]bool{}
	uuid := regexp.MustCompile(`^[a-fA-F0-9-]{36}$`)
	for _, node := range before.PingRoutes {
		if !uuid.MatchString(node.ID) || !uuid.MatchString(node.TunnelUUID) || net.ParseIP(node.Address) == nil || node.Port < 1 ||
			node.Port > 65535 ||
			seenID[node.ID] ||
			seenAddress[node.Address] {
			return nil, errors.New("replacement_exit_ping_binding_invalid")
		}
		seenID[node.ID], seenAddress[node.Address] = true, true
		if samePreservedPrimaryHost(node.Address, p.Bridge.SSHHost) || samePreservedPrimaryHost(node.Address, p.Database.PrimaryHost) {
			return nil, errors.New("replacement_exit_ping_protected_host")
		}
		static := false
		for _, ex := range p.Exits {
			address := ex.DialAddr
			if address == "" {
				address = ex.SSHHost
			}
			if address == node.Address && (ex.Port == 0 || ex.Port == node.Port) {
				static = true
			}
		}
		if !static {
			if !uuid.MatchString(node.OperationID) || node.InstanceID == "" || node.State != "ready" ||
				!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(node.Pin) {
				return nil, errors.New("replacement_exit_ping_retained_identity_unavailable")
			}
			node.Retained = true
		}
		r.Nodes = append(r.Nodes, node)
	}
	return r, nil
}

func captureReplacementPing(ctx context.Context, p *installplan.InstallPlan, rollout *replacementPingRollout, state string) error {
	if rollout == nil {
		return nil
	}
	if err := prepareReplacementPingInstaller(p, rollout); err != nil {
		return err
	}
	fallback, err := os.ReadFile(p.Automation.KnownHostsFile)
	if err != nil {
		return errors.New("replacement_exit_ping_operator_pins_unavailable")
	}
	raw, err := retainedRemote(ctx, p, p.Bridge.SSHHost, p.BridgeSSHIdentity(), false,
		replacementPingCaptureProgram, []string{string(mustReplacementJSON(rollout)), string(fallback)})
	if err != nil {
		return fmt.Errorf("replacement_exit_ping_capture_failed: %w", err)
	}
	var captured replacementPingRollout
	if json.Unmarshal(raw, &captured) != nil {
		return errors.New("replacement_exit_ping_capture_invalid")
	}
	if err := validateReplacementPingControllerAttestation(captured); err != nil {
		return err
	}
	if captured.Binding != rollout.Binding || captured.BinarySHA256 != rollout.BinarySHA256 ||
		captured.BotEnabled != rollout.BotEnabled ||
		captured.Installer != rollout.Installer || captured.InstallerSHA256 != rollout.InstallerSHA256 ||
		len(captured.Nodes) != len(rollout.Nodes) {
		return errors.New("replacement_exit_ping_capture_invalid")
	}
	for i, node := range captured.Nodes {
		expected := rollout.Nodes[i]
		node.KnownHosts = ""
		if node != expected || (node.Retained && captured.Nodes[i].KnownHosts == "") {
			return errors.New("replacement_exit_ping_capture_binding_changed")
		}
	}
	*rollout = captured
	return replaceUpgradeMetadata(filepath.Join(state, "exit-ping.json"), raw)
}

func finishReplacementPing(
	ctx context.Context,
	p *installplan.InstallPlan,
	rollout *replacementPingRollout,
	state string,
	verify func(context.Context) error,
) (result error) {
	if rollout == nil {
		return nil
	}
	program := "import base64\nworker=base64.b64decode(" + fmt.Sprintf(
		"%q",
		base64.StdEncoding.EncodeToString([]byte(replacementPingExitProgram)),
	) + ").decode()\ndispatch=base64.b64decode(" + fmt.Sprintf(
		"%q",
		base64.StdEncoding.EncodeToString([]byte(replacementPingExitDispatch)),
	) + ").decode()\npublication=base64.b64decode(" + fmt.Sprintf(
		"%q",
		base64.StdEncoding.EncodeToString([]byte(replacementPingPublicationProgram)),
	) + ").decode()\nstatus_program=base64.b64decode(" + fmt.Sprintf("%q", base64.StdEncoding.EncodeToString([]byte(replacementPingUnitStatusProgram))) + ").decode()\n" + replacementPingBridgeProgram
	var attempted []int
	defer func() {
		if result == nil {
			return
		}
		cleanup, cancel := context.WithTimeout(
			context.WithoutCancel(ctx),
			time.Duration(
				len(attempted),
			)*(replacementPingExitWait+replacementPingExitStopWait)+replacementPingPublicationWait+replacementPingPublicationStopWait+30*time.Second,
		)
		defer cancel()
		if _, err := runReplacementPingOperation(cleanup, p, rollout, program, "disable", 0); err != nil {
			result = errors.Join(result, errors.New("replacement_exit_ping_disable_unverified"))
			return
		}
		for i := len(attempted) - 1; i >= 0; i-- {
			if _, err := runReplacementPingOperation(cleanup, p, rollout, program, "rollback", attempted[i]); err != nil {
				result = errors.Join(result, errors.New("replacement_exit_ping_rollback_unverified"))
				return
			}
		}
	}()
	if _, err := runReplacementPingOperation(ctx, p, rollout, program, "stage", 0); err != nil {
		return fmt.Errorf("replacement_exit_ping_staging_failed: %w", err)
	}
	if err := verify(ctx); err != nil {
		return err
	}
	for i, node := range rollout.Nodes {
		if !node.Retained {
			continue
		}
		attempted = append(attempted, i)
		if _, err := runReplacementPingOperation(ctx, p, rollout, program, "update", i); err != nil {
			return fmt.Errorf("replacement_exit_ping_update_failed: %w", err)
		}
	}
	for i := range rollout.Nodes {
		if _, err := retainedMutation(ctx, p, p.Bridge.SSHHost, p.BridgeSSHIdentity(), false, program,
			[]string{string(mustReplacementJSON(rollout)), "probe", fmt.Sprint(i)}); err != nil {
			return fmt.Errorf("replacement_exit_ping_probe_failed: %w", err)
		}
	}
	if err := verify(ctx); err != nil {
		return err
	}
	raw, err := runReplacementPingOperation(ctx, p, rollout, program, "publish", 0)
	if err != nil {
		return fmt.Errorf("replacement_exit_ping_publication_failed: %w", err)
	}
	var receipt struct {
		Binding  string `json:"binding"`
		Verified bool   `json:"verified"`
		Count    int    `json:"count"`
	}
	if json.Unmarshal(raw, &receipt) != nil || !receipt.Verified || receipt.Binding != rollout.Binding ||
		receipt.Count != len(rollout.Nodes) {
		return errors.New("replacement_exit_ping_rollout_receipt_invalid")
	}
	return replaceUpgradeMetadata(filepath.Join(state, "exit-ping-completed.json"), raw)
}
