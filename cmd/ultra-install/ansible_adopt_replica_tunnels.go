package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/jackc/pgx/v5"
)

// Derive transport-only stages from the immutable topology and inspection. This
// bypasses the relay worker queue while the root deployment lease owns the gate.
func adoptionReplicaTunnelInventory(inventory map[string]any, topology adoptionTopology, inspection bootstrapInspection, directory, lockRoot string, index int) (map[string]any, map[string]any, error) {
	fail := func() (map[string]any, map[string]any, error) {
		return nil, nil, errors.New("adoption_replica_transport_inputs_invalid")
	}
	if index < 0 || index >= len(topology.Nodes) || !filepath.IsAbs(directory) || !filepath.IsAbs(lockRoot) {
		return fail()
	}
	node := topology.Nodes[index]
	if !node.Enabled || !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(node.ID) {
		return fail()
	}
	address, err := netip.ParseAddr(node.Address)
	if err != nil || address.String() != node.Address || address.IsUnspecified() {
		return fail()
	}
	all, _ := inventory["all"].(map[string]any)
	common, _ := all["vars"].(map[string]any)
	children, _ := all["children"].(map[string]any)
	bridges, _ := children["bridge"].(map[string]any)
	bridgeHosts, _ := bridges["hosts"].(map[string]any)
	bridge, _ := bridgeHosts["bridge"].(map[string]any)
	exits, _ := children["exits"].(map[string]any)
	exitHosts, _ := exits["hosts"].(map[string]any)
	alias := "exit_" + strconv.Itoa(index)
	replica, _ := exitHosts[alias].(map[string]any)
	identity, _ := common["ansible_ssh_private_key_file"].(string)
	if len(bridgeHosts) != 1 || bridge == nil || replica == nil || common == nil || replica["ansible_host"] != node.Address || !filepath.IsAbs(identity) {
		return fail()
	}
	pins := filepath.Join(directory, "post-gate", "topology-"+alias+".known_hosts")
	peerSSH, _ := replica["ansible_ssh_common_args"].(string)
	if !strings.HasSuffix(peerSSH, "UserKnownHostsFile="+shellQuote(pins)) {
		return fail()
	}
	pinBytes, pinErr := os.ReadFile(pins)
	if pinErr != nil || string(pinBytes) != node.Pins {
		return fail()
	}
	if err = operatorPrivate(pins, false); err != nil {
		return fail()
	}
	raw, err := inspection.file("spec.json")
	var prior config.Spec
	if err != nil || json.Unmarshal(raw, &prior) != nil || prior.Role != config.RoleBridge || prior.Database == nil || strings.TrimSpace(prior.Database.DSN) == "" {
		return fail()
	}
	database, err := pgx.ParseConfig(prior.Database.DSN)
	if err != nil || database.Port == 0 {
		return fail()
	}
	if database.Host != "127.0.0.1" && database.Host != "localhost" && database.Host != "::1" && !filepath.IsAbs(database.Host) {
		return fail()
	}
	for _, fallback := range database.Fallbacks {
		if fallback.Host != database.Host || fallback.Port != database.Port {
			return fail()
		}
	}
	variables := map[string]any{"ultra_lock_directory": lockRoot, "ultra_bootstrap_replica_host": alias, "ultra_replica_slot": "ultra_" + strings.ReplaceAll(node.ID, "-", ""), "ultra_replica_address": node.Address, "ultra_replica_primary_port": int(database.Port), "ultra_replica_identity_source": identity, "ultra_replica_known_hosts_source": pins}
	return inventory, variables, nil
}

func runAdoptionReplicaTunnels(ctx context.Context, inventory map[string]any, topology adoptionTopology, inspection bootstrapInspection, directory, lockRoot string, generation int, python, executable string) error {
	if len(topology.Nodes) == 0 || len(topology.Nodes) > 16 || generation < 1 {
		return errors.New("adoption_replica_transport_inputs_invalid")
	}
	anchor := bootstrapMutationStage(directory, "bootstrap-postgres", 1)
	anchorInfo, anchorErr := os.Lstat(anchor)
	if anchorErr != nil || !anchorInfo.IsDir() || anchorInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("adoption_replica_transport_component_anchor_required")
	}
	for index := range topology.Nodes {
		selected, variables, err := adoptionReplicaTunnelInventory(inventory, topology, inspection, directory, lockRoot, index)
		if err != nil {
			return err
		}
		stage := bootstrapMutationStage(directory, "adopt-replica-exit_"+strconv.Itoa(index), generation)
		if _, err = deployansible.RunLocalRetryFailedPinned(ctx, "adopt-replica-tunnels", selected, variables, stage, anchor, python, executable); err != nil {
			return err
		}
		if err = verifyBootstrapComponentReceipt(stage, "adopt-replica-tunnels", selected, variables); err != nil {
			return err
		}
	}
	return nil
}
