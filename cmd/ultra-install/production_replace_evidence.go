package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func checkReplacementQuiescence(ctx context.Context, p *installplan.InstallPlan, target replacementTarget, primary bool) error {
	raw, err := retainedRemote(ctx, p, target.Address, target.Identity, primary, replacementQuiescenceProgram, []string{target.Role, p.Database.Name})
	if err != nil {
		return fmt.Errorf("replacement_quiescence_probe_unavailable: %w", err)
	}
	var result struct {
		Quiescent bool   `json:"quiescent"`
		Code      string `json:"code"`
	}
	if retainedReconcileUniqueJSON(raw) != nil || json.Unmarshal(raw, &result) != nil {
		return errors.New("replacement_quiescence_result_invalid")
	}
	if !result.Quiescent {
		switch result.Code {
		case "replacement_other_root_ssh_session", "replacement_unknown_root_helper", "replacement_session_census_unavailable", "replacement_helper_session_unisolated", "replacement_tunnel_uid_unavailable", "replacement_primary_client_transactions_active", "replacement_primary_activity_unavailable":
			return errors.New(result.Code)
		default:
			return errors.New("replacement_quiescence_not_verified")
		}
	}
	return nil
}

type replacementRestoreReceipt struct {
	Protocol     string `json:"protocol"`
	BackupSHA    string `json:"backup_sha256"`
	DumpSHA      string `json:"dump_sha256"`
	SourceSHA    string `json:"source_sha256"`
	Database     string `json:"database"`
	Isolation    string `json:"isolation"`
	RestoredAt   string `json:"restored_at_utc"`
	PublicTables int    `json:"public_tables"`
	Migrations   string `json:"migration_versions"`
}

// This is a private operator execution receipt from a real isolated pg_restore,
// not a TOC/list check. The verified encrypted archive supplies all data bindings.
func validateReplacementRestoreReceipt(raw []byte, backup retainedBackupMetadata, database string, schemaMax int, now time.Time) error {
	fail := errors.New("replacement_isolated_restore_receipt_invalid")
	var receipt replacementRestoreReceipt
	if retainedReconcileUniqueJSON(raw) != nil || json.Unmarshal(raw, &receipt) != nil {
		return fail
	}
	when, err := time.Parse(time.RFC3339, receipt.RestoredAt)
	if err != nil || when.Before(backup.SnapshotStarted) || when.After(now.Add(5*time.Second)) || now.Sub(when) > 30*time.Minute {
		return fail
	}
	if schemaMax < 1 || schemaMax > 10000 {
		return fail
	}
	versions := make([]string, schemaMax)
	for n := range versions {
		versions[n] = strconv.Itoa(n + 1)
	}
	if receipt.Protocol != "ultra-isolated-primary-restore-v1" || receipt.BackupSHA != backup.EncryptedSHA256 || receipt.DumpSHA != backup.DumpSHA256 || receipt.SourceSHA != backup.ExpectedSourceSHA || receipt.Database != database || receipt.Isolation != "postgres-network-none" || receipt.PublicTables < 1 || receipt.Migrations != strings.Join(versions, ",") {
		return fail
	}
	return nil
}

func replacementJournalInput(path string) ([]byte, error) {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil, nil
	}
	raw, err := readRebuildInput(path, true)
	if err != nil {
		return nil, err
	}
	var record map[string]json.RawMessage
	if retainedReconcileUniqueJSON(raw) != nil || json.Unmarshal(raw, &record) != nil {
		return nil, errors.New("replacement_previous_journal_invalid")
	}
	return raw, nil
}

func replacementPreviousTargets(raw []byte, previousPath string, current *installplan.InstallPlan, targets []replacementTarget) ([]replacementTarget, error) {
	if len(raw) == 0 {
		return targets, nil
	}
	var record struct {
		Dispatched *bool  `json:"mutator_dispatched"`
		ConfigSHA  string `json:"config_sha256"`
	}
	if json.Unmarshal(raw, &record) != nil || record.Dispatched == nil {
		return nil, errors.New("replacement_previous_journal_dispatch_unknown")
	}
	if !*record.Dispatched {
		return targets, nil
	}
	previous, err := readRebuildInput(previousPath, true)
	if err != nil || !retainedBackupSHA.MatchString(record.ConfigSHA) || digestSHA256(previous) != record.ConfigSHA {
		return nil, errors.New("replacement_exact_dispatched_config_required")
	}
	p, err := installplan.LoadConfig(previousPath)
	if err != nil {
		return nil, errors.New("replacement_previous_config_invalid")
	}
	unchanged, err := readRebuildInput(previousPath, true)
	if err != nil || string(unchanged) != string(previous) {
		return nil, errors.New("replacement_previous_config_changed")
	}
	return unionReplacementPreviousTargets(current, p, targets)
}

func unionReplacementPreviousTargets(current, p *installplan.InstallPlan, targets []replacementTarget) ([]replacementTarget, error) {
	if !samePreservedPrimaryHost(p.Database.PrimaryHost, current.Database.PrimaryHost) {
		return nil, errors.New("replacement_previous_primary_changed")
	}
	old, err := replacementTargets(p)
	if err != nil {
		return nil, err
	}
	for _, target := range old {
		found := false
		for _, existing := range targets {
			if samePreservedPrimaryHost(existing.Address, target.Address) {
				found = true
			}
		}
		if !found {
			target.Role = "former-" + strconv.Itoa(len(targets))
			targets = append(targets, target)
		}
	}
	return targets, nil
}
