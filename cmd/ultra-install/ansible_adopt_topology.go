package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type adoptionTopology struct {
	Nodes  []adoptionTopologyNode `json:"nodes"`
	SHA256 string                 `json:"sha256"`
}
type adoptionTopologyNode struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Address    string `json:"address"`
	Port       int    `json:"port"`
	TunnelUUID string `json:"tunnel_uuid"`
	CertPin    string `json:"pinned_peer_cert_sha256"`
	Priority   int    `json:"priority"`
	Enabled    bool   `json:"enabled"`
	Pins       string `json:"pins"`
}

// Discovery is a bridge-only read. Retries attest the original derived topology
// snapshot independently of the operator plan and never replace its identities.
func inspectAdoptionTopology(
	ctx context.Context,
	p *installplan.InstallPlan,
	directory, python, executable, lockRoot string,
) (adoptionTopology, error) {
	var frozen adoptionTopology
	target := filepath.Join(directory, "topology.frozen.json")
	expected := ""
	if raw, err := os.ReadFile(target); err == nil {
		if err = operatorPrivate(target, false); err != nil {
			return frozen, err
		}
		if err = json.Unmarshal(raw, &frozen); err != nil || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(frozen.SHA256) {
			return frozen, errors.New("adoption_topology_frozen_invalid")
		}
		expected = frozen.SHA256
	} else if !os.IsNotExist(err) {
		return frozen, err
	}
	bridgeOnly := *p
	bridgeOnly.Exits = nil
	inventory, err := bootstrapInventory(&bridgeOnly, directory)
	if err != nil {
		return frozen, err
	}
	if err = os.MkdirAll(filepath.Join(directory, "inspection"), 0700); err != nil {
		return frozen, err
	}
	probeDirectory, err := os.MkdirTemp(directory, "topology-probe-")
	if err != nil {
		return frozen, err
	}
	defer os.RemoveAll(probeDirectory) //nolint:errcheck
	_, err = deployansible.RunLocal(
		ctx,
		"adopt-topology",
		inventory,
		map[string]any{"ultra_lock_directory": lockRoot, "ultra_topology_database": p.Database.Name, "ultra_topology_expected": expected},
		filepath.Join(probeDirectory, "operation"),
		python,
		executable,
	)
	if err != nil {
		return frozen, err
	}
	raw, err := os.ReadFile(filepath.Join(directory, "inspection", "topology.json"))
	if err != nil {
		return frozen, err
	}
	var observed adoptionTopology
	if err = json.Unmarshal(raw, &observed); err != nil || len(observed.Nodes) == 0 || len(observed.Nodes) > 16 ||
		!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(observed.SHA256) {
		return frozen, errors.New("adoption_topology_probe_invalid")
	}
	if expected != "" {
		if observed.SHA256 != expected || !reflect.DeepEqual(observed.Nodes, frozen.Nodes) {
			return frozen, errors.New("adoption_topology_changed")
		}
		return frozen, nil
	}
	if err = writeBootstrapFrozenFile(target, raw); err != nil {
		return frozen, err
	}
	return observed, nil
}

// Use DB names consistently for desired state and numeric inventory aliases.
// Static configuration and bootstrap history cannot re-enable a disabled row.
func applyAdoptionTopology(
	p *installplan.InstallPlan,
	inventory map[string]any,
	directory string,
	topology adoptionTopology,
) ([]exits.BootstrapEntry, error) {
	if len(topology.Nodes) == 0 || len(topology.Nodes) > 16 {
		return nil, errors.New("adoption_topology_bounds")
	}
	nodes := map[string]any{}
	entries := []exits.BootstrapEntry{}
	enabled := true
	planExits := []installplan.ExitNode{}
	seen := map[string]bool{}
	for index, node := range topology.Nodes {
		if !node.Enabled || node.Name == "" || seen[node.Name] || node.Pins == "" || len(node.Pins) > 65536 || node.TunnelUUID == "" ||
			node.CertPin == "" ||
			node.Port < 1 ||
			node.Port > 65535 ||
			node.Priority < 1 {
			return nil, errors.New("adoption_topology_invalid")
		}
		seen[node.Name] = true
		alias := "exit_" + strconv.Itoa(index)
		pinPath := filepath.Join(directory, "topology-"+alias+".known_hosts")
		if previous, err := os.ReadFile(pinPath); err == nil {
			if err = operatorPrivate(pinPath, false); err != nil {
				return nil, err
			}
			if string(previous) != node.Pins {
				return nil, errors.New("adoption_topology_pins_changed")
			}
		} else if os.IsNotExist(err) {
			if err = writeBootstrapFrozenFile(pinPath, []byte(node.Pins)); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
		nodes[alias] = map[string]any{
			"ansible_host":   node.Address,
			"ansible_user":   "root",
			"ansible_become": false,
			"ansible_ssh_common_args": "-F /dev/null -o ControlMaster=no -o ControlPath=none -o UpdateHostKeys=no -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=" + shellQuote(
				pinPath,
			),
		}
		planExits = append(
			planExits,
			installplan.ExitNode{
				Name:       node.Name,
				SSHHost:    node.Address,
				DialAddr:   node.Address,
				Port:       node.Port,
				Priority:   node.Priority,
				Enabled:    &enabled,
				TunnelUUID: node.TunnelUUID,
			},
		)
		entries = append(
			entries,
			exits.BootstrapEntry{
				Name:                 node.Name,
				Address:              node.Address,
				Port:                 node.Port,
				TunnelUUID:           node.TunnelUUID,
				Priority:             node.Priority,
				Enabled:              exits.BootstrapEnabledPtr(true),
				PinnedPeerCertSHA256: node.CertPin,
			},
		)
	}
	all, ok := inventory["all"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("adoption_inventory_invalid")
	}
	children, ok := all["children"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("adoption_inventory_invalid")
	}
	children["exits"] = map[string]any{"hosts": nodes}
	p.Exits = planExits
	return entries, nil
}

// Attest installed exit identity and actual certificate before adopting DB routes.
func validateAdoptionTopologyInspection(topology adoptionTopology, inspection map[string]bootstrapInspection) error {
	for index, node := range topology.Nodes {
		observed, ok := inspection["exit_"+strconv.Itoa(index)]
		if !ok || observed.CertificatePin != node.CertPin {
			return errors.New("adoption_topology_certificate_conflict")
		}
		raw, err := observed.file("spec.json")
		var specification config.Spec
		if err != nil || len(raw) == 0 || json.Unmarshal(raw, &specification) != nil || specification.Role != config.RoleExit ||
			specification.VLESSPort != node.Port ||
			specification.Exit.TunnelUUID != node.TunnelUUID {
			return errors.New("adoption_topology_exit_identity_conflict")
		}
	}
	return nil
}
