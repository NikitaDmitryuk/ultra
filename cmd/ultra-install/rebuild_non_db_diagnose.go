package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"
)

// Diagnosis is a requirements report, never a receipt. It reads only the
// supplied journal: even well-formed journal bindings prove neither historical
// fleet completeness nor the absence of surviving or newly dispatched workers.
type rebuildDiagnosis struct {
	Protocol           string   `json:"protocol"`
	State              string   `json:"state"`
	JournalSHA         string   `json:"original_journal_sha256"`
	GateReleased       bool     `json:"gate_released"`
	ExecutionSupported bool     `json:"execution_supported"`
	EvidenceCollected  bool     `json:"evidence_collected"`
	Blockers           []string `json:"blockers"`
}

func diagnoseRebuildNonDB(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("rebuild-non-db diagnose", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	journalPath := flags.String("original-journal", "", "forward-only upgrade journal (read only)")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return errors.New("rebuild_non_db_arguments_invalid")
	}
	if !filepath.IsAbs(*journalPath) || filepath.Clean(*journalPath) != *journalPath {
		return errors.New("rebuild_non_db_paths_invalid")
	}
	raw, err := readRebuildInput(*journalPath, true)
	if err != nil {
		return err
	}
	// A map permits existing/future manual journal metadata without treating any
	// supplied claims as authority; rebuildDecode still rejects duplicate keys.
	var journal map[string]json.RawMessage
	if rebuildDecode(raw, &journal) != nil || journal == nil {
		return errors.New("rebuild_non_db_journal_invalid")
	}
	var schema int
	var stage string
	var dispatched, forward bool
	if json.Unmarshal(journal["schema"], &schema) != nil || schema != 1 ||
		json.Unmarshal(journal["stage"], &stage) != nil || stage != "upgrade" ||
		json.Unmarshal(journal["mutator_dispatched"], &dispatched) != nil || !dispatched ||
		json.Unmarshal(journal["forward_only"], &forward) != nil || !forward {
		return errors.New("rebuild_non_db_forward_upgrade_required")
	}
	report := rebuildDiagnosis{
		Protocol: "ultra-rebuild-non-db-diagnosis-v1", State: "blocked-evidence-not-collected",
		JournalSHA: digestSHA256(raw),
		Blockers: []string{
			"exact_persisted_prior_target_manifest_and_predecessor_chain_required",
			"independent_local_dispatch_and_mutator_quiescence_required",
			"independent_remote_mutator_quiescence_or_destruction_required",
			"trusted_operation_bound_reimage_receipts_for_all_former_targets_required",
			"retained_primary_identity_and_target_exclusion_required",
			"fresh_independent_backup_digest_primary_and_config_binding_required",
			"retained_primary_connectivity_and_authorization_required",
			"trusted_journal_bound_completion_and_retirement_protocol_required",
		},
	}
	if err := json.NewEncoder(output).Encode(report); err != nil {
		return err
	}
	return errRebuildBlocked
}
