package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"sort"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"github.com/google/uuid"
)

// This is the complete durable registry, including disabled/deleted nodes. No
// user, subscription, provider credential or route UUID is part of this scope.
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

func verifyBridgeReimageProvider(
	ctx context.Context,
	p *installplan.InstallPlan,
	proof *recoveryBridgeReimage,
	in retainedPrimaryRebuildInput,
) ([]bridgeReimageFleetRow, error) {
	live, ids, err := validateBridgeReimageFleet(proof.Fleet, in)
	if err != nil {
		return nil, err
	}
	if err = selectPlanSecrets(p, "installed-runtime"); err != nil {
		return nil, errors.New("bridge_reimage_provider_identity_unavailable")
	}
	values, err := readProviderSecretValues(p)
	if err != nil || strings.TrimSpace(values["ULTRA_VULTR_API_KEY"]) == "" {
		return nil, errors.New("bridge_reimage_provider_identity_unavailable")
	}
	api := cloud.NewVultr(strings.TrimSpace(values["ULTRA_VULTR_API_KEY"]))
	raw, _ := json.Marshal(ids)
	var census providerCensusReceipt
	if len(ids) > 0 {
		census, err = collectProviderCensus(ctx, api, ids, digestSHA256(raw))
	} else {
		var rows []cloud.Instance
		rows, err = api.Instances(ctx)
		for _, row := range rows {
			census.Instances = append(census.Instances, providerCensusInstance{row.ID, row.IP, true})
		}
	}
	if err != nil {
		return nil, err
	}
	if err = verifyBridgeReimageProviderScope(census, p, ids); err != nil {
		return nil, err
	}
	observed := map[string]providerCensusInstance{}
	for _, row := range census.Requested {
		observed[row.ID] = row
	}
	for _, row := range proof.Fleet {
		if row.Kind != "cloud_operation" || row.State == "cancelled" {
			continue
		}
		value := observed[row.InstanceID]
		if (row.State == "ready") != value.Present {
			return nil, errors.New("bridge_reimage_provider_state_changed")
		}
	}
	for _, row := range live {
		if observed[row.InstanceID].Address != row.Address {
			return nil, errors.New("bridge_reimage_provider_address_changed")
		}
	}
	return live, nil
}

func equalBridgeReimageFleet(a, b []bridgeReimageFleetRow) bool {
	x := append([]bridgeReimageFleetRow{}, a...)
	y := append([]bridgeReimageFleetRow{}, b...)
	for _, rows := range [][]bridgeReimageFleetRow{x, y} {
		sort.Slice(rows, func(i, j int) bool { return rows[i].Kind+rows[i].ID < rows[j].Kind+rows[j].ID })
	}
	return reflect.DeepEqual(x, y)
}

// A newly tombstoned node is bound to its transaction receipt, rather than
// rewritten into a fictitious historical provider-deleted inventory.
func validateBridgeReimageRetirement(proof *recoveryBridgeReimage) error {
	count := 0
	for _, row := range proof.Fleet {
		if row.RetirementBinding != "" {
			count++
		}
	}
	if count == 0 && len(proof.Retirement) == 0 {
		return nil
	}
	var receipt struct {
		Protocol      string `json:"protocol"`
		Binding       string `json:"binding_sha256"`
		Deletion      string `json:"deletion_sha256"`
		OperationID   string `json:"operation_id"`
		ExitID        string `json:"exit_id"`
		InstanceID    string `json:"instance_id"`
		ExitRows      int    `json:"exit_rows"`
		OperationRows int    `json:"operation_rows"`
		RouteRows     int    `json:"route_rows"`
		EventRows     int    `json:"event_rows"`
	}
	fail := errors.New("bridge_reimage_retirement_receipt_unverified")
	if count != 1 || decodeRetainedReconcile(proof.Retirement, &receipt) != nil || receipt.Protocol != "ultra-provider-absence-retirement-v1" ||
		!runtimeHostValidDigest(receipt.Binding) ||
		!runtimeHostValidDigest(receipt.Deletion) ||
		receipt.ExitRows != 1 ||
		receipt.OperationRows != 1 ||
		receipt.EventRows != 1 ||
		receipt.RouteRows < 0 {
		return fail
	}
	for _, row := range proof.Fleet {
		if row.RetirementBinding != "" {
			if row.Kind != "cloud_operation" || row.ID != receipt.OperationID || row.ExitID != receipt.ExitID ||
				row.InstanceID != receipt.InstanceID ||
				row.RetirementBinding != receipt.Binding ||
				row.State != "deleted" ||
				row.Phase != "cleanup" ||
				row.OccupiesSlot {
				return fail
			}
		}
	}
	return nil
}

func verifyBridgeReimageProviderScope(census providerCensusReceipt, p *installplan.InstallPlan, ids []string) error {
	known := map[string]bool{}
	for _, id := range ids {
		known[id] = true
	}
	static := map[string]bool{p.Bridge.Address: true, p.Bridge.SSHHost: true, p.Database.PrimaryHost: true}
	for _, exit := range p.Exits {
		static[exit.SSHHost] = true
		static[exit.DialAddr] = true
	}
	for _, row := range census.Instances {
		if !known[row.ID] && !static[row.Address] {
			return errors.New("bridge_reimage_provider_unregistered_target")
		}
	}
	return nil
}
