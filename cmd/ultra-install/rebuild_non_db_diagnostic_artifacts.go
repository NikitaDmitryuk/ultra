package main

import (
	"errors"
	"path/filepath"
	"sort"
	"strings"
)

// These are byte fingerprints of explicitly supplied files. Kind is chosen by
// the caller, not established by a parser or trusted collector. Neither a
// fingerprint nor a matched journal pin supplies provenance or authority.
type rebuildDiagnosticArtifact struct {
	Kind      string `json:"kind"`
	SHA256    string `json:"sha256"`
	SizeBytes int    `json:"size_bytes"`
	Verified  bool   `json:"verified"`
}

type rebuildDiagnosticRequirement struct {
	Code           string `json:"code"`
	EvidenceKind   string `json:"evidence_kind"`
	RequiredSource string `json:"required_source"`
	Binding        string `json:"binding"`
}

type rebuildDiagnosticInputs []string

func (inputs *rebuildDiagnosticInputs) String() string { return "" }

func (inputs *rebuildDiagnosticInputs) Set(value string) error {
	if len(*inputs) >= 32 {
		return errors.New("rebuild_non_db_artifact_limit_exceeded")
	}
	*inputs = append(*inputs, value)
	return nil
}

func rebuildDiagnosticRequirements() []rebuildDiagnosticRequirement {
	return []rebuildDiagnosticRequirement{
		{
			Code:           "exact_persisted_prior_target_manifest_and_predecessor_chain_required",
			EvidenceKind:   "historical-targets",
			RequiredSource: "independently preserved original activate request, job and receipt; all predecessor journals",
			Binding:        "exact original journal SHA and request/job/receipt digests; every former target identity and provider account; current config or release manifest is insufficient",
		},
		{
			Code:           "independent_local_dispatch_and_mutator_quiescence_required",
			EvidenceKind:   "local-quiescence",
			RequiredSource: "independent collector outside the rebuilt fleet with enforced dispatch fencing",
			Binding:        "original operation and all dispatchers, controller descendants and Ansible processes; free locks and missing PIDs alone are insufficient",
		},
		{
			Code:           "independent_remote_mutator_quiescence_or_destruction_required",
			EvidenceKind:   "remote-quiescence",
			RequiredSource: "independent worker collector and complete paginated provider inventories for all historical accounts",
			Binding:        "every former target, provider/account ownership, pinned host identity and worker outcome; current absence or unreachable SSH is insufficient",
		},
		{
			Code:           "trusted_operation_bound_reimage_receipts_for_all_former_targets_required",
			EvidenceKind:   "provider-outcomes",
			RequiredSource: "authoritative provider reimage/delete operation records and completed outcomes",
			Binding:        "original journal, each former provider/account/instance, operation ID and completion time; operator assertions and current inventory cannot prove historical destruction",
		},
		{
			Code:           "retained_primary_identity_and_target_exclusion_required",
			EvidenceKind:   "retained-primary",
			RequiredSource: "independently authenticated retained primary observations under verified writer fencing",
			Binding:        "provider/account/instance, PostgreSQL system identifier, database OID, primary role, migration state and connection binding; exclude this identity from every mutation",
		},
		{
			Code:           "fresh_independent_backup_digest_primary_and_config_binding_required",
			EvidenceKind:   "independent-backup",
			RequiredSource: "fresh backup receipt from an independently verified receiver and isolated restore verification",
			Binding:        "backup artifact digest, exact retained primary and canonical config, consistent collection after writer fencing; a dump filename, TOC or digest alone is insufficient",
		},
		{
			Code:           "retained_primary_connectivity_and_authorization_required",
			EvidenceKind:   "primary-connectivity",
			RequiredSource: "authenticated connection observation from replacement bridge using the existing authorization; public escrow metadata only",
			Binding:        "pinned primary identity, preserved tunnel public identity and application database; private keys and DSNs must not be submitted; relay startup must not apply unapproved migrations",
		},
		{
			Code:           "trusted_journal_bound_completion_and_retirement_protocol_required",
			EvidenceKind:   "completion-protocol",
			RequiredSource: "implemented independent verifier, controller and wrapper completion protocol with preprovisioned authority",
			Binding:        "exact original journal and predecessors, candidate, fleet and immutable primary; durable intent/outcome reconciliation, crash replay and request-bound receipt before gate release; unsupported today",
		},
	}
}

func collectRebuildDiagnosticArtifacts(
	inputs rebuildDiagnosticInputs,
	journalPath string,
	requirements []rebuildDiagnosticRequirement,
) ([]rebuildDiagnosticArtifact, error) {
	kinds := make(map[string]bool, len(requirements))
	for _, requirement := range requirements {
		kinds[requirement.EvidenceKind] = true
	}
	seen := map[string]bool{journalPath: true}
	result := make([]rebuildDiagnosticArtifact, 0, len(inputs))
	for _, input := range inputs {
		kind, path, found := strings.Cut(input, "=")
		if !found || !kinds[kind] || !filepath.IsAbs(path) || filepath.Clean(path) != path ||
			seen[path] {
			return nil, errors.New("rebuild_non_db_artifact_invalid")
		}
		seen[path] = true
		raw, err := readRebuildInput(path, true)
		if err != nil {
			return nil, err
		}
		result = append(
			result,
			rebuildDiagnosticArtifact{Kind: kind, SHA256: digestSHA256(raw), SizeBytes: len(raw)},
		)
	}
	// CLI argument ordering cannot change the meaning of repeated intake reports.
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind != result[j].Kind {
			return result[i].Kind < result[j].Kind
		}
		return result[i].SHA256 < result[j].SHA256
	})
	return result, nil
}
