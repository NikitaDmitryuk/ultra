package main

import (
	"context"
	"errors"
	"net"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
)

type rebuildInstanceReader interface {
	Instances(context.Context) ([]cloud.Instance, error)
}

type rebuildInstanceMapping struct {
	ID         string
	InstanceID string
	Address    string
	Role       string
	OwnerTag   string
	RoleTag    string
}

// collectRebuildProviderInventory consumes the existing paginated read-only
// provider API. It proves exact mapping only within the supplied account. It
// does not prove that this account covers the historic fleet, authenticate SSH
// hosts, prove workers stopped or establish retained-primary database identity.
// It is not wired to CLI credentials until those independent contracts exist.
func collectRebuildProviderInventory(
	ctx context.Context,
	provider rebuildInstanceReader,
	mapping []rebuildInstanceMapping,
) ([]cloud.Instance, error) {
	if provider == nil || len(mapping) < 3 || len(mapping) > 1025 {
		return nil, errors.New("rebuild_provider_mapping_invalid")
	}
	byInstance := map[string]rebuildInstanceMapping{}
	ids, addresses := map[string]bool{}, map[string]bool{}
	bridges, primaries, exits := 0, 0, 0
	for _, entry := range mapping {
		if !rebuildLabel.MatchString(entry.ID) || !rebuildLabel.MatchString(entry.InstanceID) ||
			!rebuildLabel.MatchString(entry.OwnerTag) || net.ParseIP(entry.Address) == nil ||
			byInstance[entry.InstanceID].ID != "" || ids[entry.ID] || addresses[net.ParseIP(entry.Address).String()] {
			return nil, errors.New("rebuild_provider_mapping_invalid")
		}
		switch entry.Role {
		case "bridge":
			bridges++
		case "exit":
			exits++
		case "primary":
			primaries++
		default:
			return nil, errors.New("rebuild_provider_mapping_invalid")
		}
		byInstance[entry.InstanceID], ids[entry.ID], addresses[net.ParseIP(entry.Address).String()] = entry, true, true
	}
	if bridges != 1 || primaries != 1 || exits == 0 {
		return nil, errors.New("rebuild_provider_mapping_invalid")
	}
	instances, err := provider.Instances(ctx)
	if err != nil {
		return nil, errors.New("rebuild_provider_inventory_unavailable")
	}
	if len(instances) != len(mapping) {
		return nil, errors.New("rebuild_provider_inventory_incomplete_or_unknown")
	}
	seen := map[string]bool{}
	seenAddresses := map[string]bool{}
	for _, instance := range instances {
		entry, found := byInstance[instance.ID]
		owned := false
		roleMatched := entry.RoleTag == ""
		for _, tag := range instance.Tags {
			if tag == entry.OwnerTag {
				owned = true
			}
			if tag == entry.RoleTag {
				roleMatched = true
			}
		}
		ip := net.ParseIP(instance.IP)
		if !found || ip == nil || seen[instance.ID] || !ip.Equal(net.ParseIP(entry.Address)) || !owned || !roleMatched ||
			instance.Status != "active" || instance.ServerStatus != "ok" || instance.PowerStatus != "running" {
			return nil, errors.New("rebuild_provider_identity_unverified")
		}
		if seenAddresses[ip.String()] {
			return nil, errors.New("rebuild_provider_identity_unverified")
		}
		seenAddresses[ip.String()] = true
		seen[instance.ID] = true
	}
	return instances, nil
}
