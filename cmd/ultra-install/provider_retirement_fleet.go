package main

import (
	"encoding/json"
	"errors"
	"net"
	"sort"

	"github.com/google/uuid"
)

type bridgeReimageFleetRow struct {
	RetirementBinding string `json:"retirement_binding"`
	Kind              string `json:"kind"`
	ID                string `json:"id"`
	Address           string `json:"address"`
	Port              int    `json:"port"`
	Enabled           bool   `json:"enabled"`
	Pin               string `json:"pinned_peer_cert_sha256"`
	State             string `json:"state"`
	Phase             string `json:"phase"`
	InstanceID        string `json:"instance_id"`
	ExitID            string `json:"exit_id"`
	OccupiesSlot      bool   `json:"occupies_slot"`
	InstallAttempt    string `json:"install_attempt"`
}

func normalizeBridgeReimageFleet(raw []byte) ([]bridgeReimageFleetRow, error) {
	var rows []bridgeReimageFleetRow
	// Source inventory may contain auxiliary observation timestamps; only the
	// fixed fields above form the transport scope. Duplicate JSON keys still fail.
	if retainedReconcileUniqueJSON(raw) != nil || json.Unmarshal(raw, &rows) != nil || len(rows) == 0 || len(rows) > 20000 {
		return nil, errors.New("bridge_reimage_fleet_inventory_invalid")
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Kind+rows[i].ID < rows[j].Kind+rows[j].ID })
	return rows, nil
}

func validateBridgeReimageFleet(rows []bridgeReimageFleetRow, in retainedPrimaryRebuildInput) ([]bridgeReimageFleetRow, []string, error) {
	fail := errors.New("bridge_reimage_fleet_scope_unresolved")
	exits := map[string]bridgeReimageFleetRow{}
	ops := map[string]bool{}
	instances := map[string]bool{}
	linked := map[string]bool{}
	main, _ := retainedInventoryHost(in, "exits", "exit_0")["ansible_host"].(string)
	for _, r := range rows {
		if uuid.Validate(r.ID) != nil {
			return nil, nil, fail
		}
		if r.Kind == "exit" {
			if _, ok := exits[r.ID]; ok || net.ParseIP(r.Address) == nil || r.Port < 1 || r.Port > 65535 {
				return nil, nil, fail
			}
			exits[r.ID] = r
		} else if r.Kind != "cloud_operation" {
			return nil, nil, fail
		}
	}
	live := []bridgeReimageFleetRow{}
	ids := []string{}
	for _, r := range rows {
		if r.Kind != "cloud_operation" {
			continue
		}
		if ops[r.ID] {
			return nil, nil, fail
		}
		ops[r.ID] = true
		if r.State == "cancelled" {
			if r.InstanceID != "" || r.ExitID != "" || r.OccupiesSlot {
				return nil, nil, fail
			}
			continue
		}
		if (r.State != "ready" && r.State != "deleted") || !providerCensusID.MatchString(r.InstanceID) || instances[r.InstanceID] ||
			linked[r.ExitID] {
			return nil, nil, fail
		}
		exit, ok := exits[r.ExitID]
		if !ok || exit.Address == main {
			return nil, nil, fail
		}
		instances[r.InstanceID] = true
		linked[r.ExitID] = true
		ids = append(ids, r.InstanceID)
		if r.State == "deleted" {
			if exit.Enabled || r.OccupiesSlot {
				return nil, nil, fail
			}
		} else {
			if !exit.Enabled || !r.OccupiesSlot || !runtimeHostValidDigest(exit.Pin) || r.InstallAttempt == "" {
				return nil, nil, fail
			}
			exit.InstanceID = r.InstanceID
			live = append(live, exit)
		}
	}
	permanent := 0
	for id, r := range exits {
		if linked[id] {
			continue
		}
		if r.Address != main || !r.Enabled {
			return nil, nil, fail
		}
		permanent++
	}
	if permanent != 1 {
		return nil, nil, fail
	}
	sort.Strings(ids)
	return live, ids, nil
}
