package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"path/filepath"
)

// Diagnosis is a requirements report, never a receipt. It reads only explicitly
// supplied local files: even well-formed bindings prove neither historical
// fleet completeness nor the absence of surviving or newly dispatched workers.
type rebuildDiagnosis struct {
	Protocol           string                         `json:"protocol"`
	State              string                         `json:"state"`
	JournalSHA         string                         `json:"original_journal_sha256"`
	GateReleased       bool                           `json:"gate_released"`
	ExecutionSupported bool                           `json:"execution_supported"`
	EvidenceCollected  bool                           `json:"evidence_collected"`
	Blockers           []string                       `json:"blockers"`
	JournalPinMatched  bool                           `json:"journal_pin_matched"`
	ArtifactsVerified  bool                           `json:"artifacts_verified"`
	Artifacts          []rebuildDiagnosticArtifact    `json:"unverified_artifacts"`
	Requirements       []rebuildDiagnosticRequirement `json:"requirements"`
}

func diagnoseRebuildNonDB(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("rebuild-non-db diagnose", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	journalPath := flags.String("original-journal", "", "forward-only upgrade journal (read only)")
	expectedSHA := flags.String(
		"expected-journal-sha256",
		"",
		"expected exact journal bytes; required for artifact intake",
	)
	var artifacts rebuildDiagnosticInputs
	flags.Var(
		&artifacts,
		"artifact",
		"unverified local evidence: kind=/absolute/private/file (repeatable)",
	)
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return errors.New("rebuild_non_db_arguments_invalid")
	}
	if !filepath.IsAbs(*journalPath) || filepath.Clean(*journalPath) != *journalPath {
		return errors.New("rebuild_non_db_paths_invalid")
	}
	if (*expectedSHA != "" && !rebuildSHA.MatchString(*expectedSHA)) ||
		(len(artifacts) > 0 && *expectedSHA == "") {
		return errors.New("rebuild_non_db_journal_pin_required_or_invalid")
	}
	raw, err := readRebuildInput(*journalPath, true)
	if err != nil {
		return err
	}
	journalSHA := digestSHA256(raw)
	if *expectedSHA != "" && journalSHA != *expectedSHA {
		return errors.New("rebuild_non_db_journal_pin_mismatch")
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
		JournalSHA: journalSHA, JournalPinMatched: *expectedSHA != "",
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
	report.Requirements = rebuildDiagnosticRequirements()
	report.Artifacts, err = collectRebuildDiagnosticArtifacts(
		artifacts,
		*journalPath,
		report.Requirements,
	)
	if err != nil {
		return err
	}
	// An intake report binds the same journal before and after reading artifacts.
	// This detects changes during collection; it is not a dispatcher lease and
	// does not establish quiescence or authenticate the caller's chosen pin.
	after, err := readRebuildInput(*journalPath, true)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, after) {
		return errors.New("rebuild_non_db_journal_changed")
	}
	if err := json.NewEncoder(output).Encode(report); err != nil {
		return err
	}
	return errRebuildBlocked
}
