package main

// Bridge reimage is a distinct terminal outcome. It never proves that the
// superseded operation did not mutate, and never reconstructs its executor.
import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

const bridgeReimageAcknowledgement = "bridge-reimaged-retained-primary-and-exit-preserved"

type recoveryBridgeReimage struct {
	Retirement      []byte                  `json:"retirement,omitempty"`
	Fleet           []bridgeReimageFleetRow `json:"fleet"`
	Acknowledgement string                  `json:"acknowledgement"`
	OldConfig       []byte                  `json:"old_config"`
	SourceSpec      []byte                  `json:"source_spec"`
	LegacyJournal   []byte                  `json:"legacy_journal"`
	Descriptor      []byte                  `json:"descriptor"`
}

func reimageJournal(raw []byte) (map[string]json.RawMessage, error) {
	var j map[string]json.RawMessage
	if retainedReconcileUniqueJSON(raw) != nil || json.Unmarshal(raw, &j) != nil {
		return nil, errors.New("bridge_reimage_journal_invalid")
	}
	var schema int
	_ = json.Unmarshal(j["schema"], &schema)
	if schema != 1 || string(j["supervised_deploy"]) != "true" || string(j["mutator_dispatched"]) != "true" ||
		string(j["adopt"]) != "false" || string(j["forward_only"]) != "false" ||
		(reimageJournalString(j, "stage") != "upgrade" && reimageJournalString(j, "stage") != "status") {
		return nil, errors.New("bridge_reimage_supervised_dispatch_required")
	}
	for _, key := range []string{"config_sha256", "manifest_sha256", "remote_attempt", "transport_binding", "preparation_sha256", "preparation_descriptor_sha256", "preparation_source_spec_sha256", "preparation_legacy_journal_sha256"} {
		if !runtimeHostValidDigest(reimageJournalString(j, key)) {
			return nil, errors.New("bridge_reimage_journal_binding_missing")
		}
	}
	if reimageJournalString(
		j,
		"preparation_source_archive",
	) != "recovery-source-"+reimageJournalString(
		j,
		"preparation_legacy_journal_sha256",
	) {
		return nil, errors.New("bridge_reimage_archive_binding_invalid")
	}
	return j, nil
}

func reimageJournalString(j map[string]json.RawMessage, key string) string {
	var value string
	_ = json.Unmarshal(j[key], &value)
	return value
}

func validateRecoveryBridgeReimage(proof *recoveryBridgeReimage, journal []byte, in retainedPrimaryRebuildInput) error {
	fail := errors.New("bridge_reimage_chain_unverified")
	if proof == nil || proof.Acknowledgement != bridgeReimageAcknowledgement || !in.BridgeOnly || in.RetainedExit == nil ||
		in.JournalSHA256 != digestSHA256(journal) {
		return fail
	}
	if live, _, err := validateBridgeReimageFleet(proof.Fleet, in); err != nil {
		return err
	} else if len(live) != 0 {
		return errors.New("bridge_reimage_live_dynamic_targets_unsupported")
	}
	if err := validateBridgeReimageRetirement(proof); err != nil {
		return err
	}
	j, err := reimageJournal(journal)
	if err != nil {
		return err
	}
	if digestSHA256(proof.OldConfig) != reimageJournalString(j, "config_sha256") ||
		digestSHA256(proof.SourceSpec) != reimageJournalString(j, "preparation_source_spec_sha256") ||
		digestSHA256(proof.LegacyJournal) != reimageJournalString(j, "preparation_legacy_journal_sha256") ||
		digestSHA256(proof.Descriptor) != reimageJournalString(j, "preparation_descriptor_sha256") {
		return fail
	}
	var old recoveryInputSnapshot
	if decodeRetainedReconcile(proof.Descriptor, &old) != nil || old.Request.BridgeReimage != nil ||
		old.Request.RetainedFenceSHA256 != in.RetainedExit.FenceSHA256 ||
		old.Request.LegacyJournalSHA256 != digestSHA256(proof.LegacyJournal) ||
		old.Request.ToolsManifestSHA256 != reimageJournalString(j, "manifest_sha256") {
		return fail
	}
	if _, err = parseBridgePreflightJournal(proof.LegacyJournal); err != nil {
		return fail
	}
	return nil
}

// Recompute the OLD export descriptor from the exact retained source archive.
// A path list or operator assertion cannot substitute for its bound bytes.
func buildRecoveryBridgeReimage(s recoveryInputSources, journal []byte, in retainedPrimaryRebuildInput) (*recoveryBridgeReimage, error) {
	j, err := reimageJournal(journal)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(s.BridgeReimageConfig) || !filepath.IsAbs(s.BridgeReimageArchive) ||
		filepath.Base(s.BridgeReimageArchive) != reimageJournalString(j, "preparation_source_archive") {
		return nil, errors.New("bridge_reimage_frozen_archive_required")
	}
	proof := &recoveryBridgeReimage{Acknowledgement: bridgeReimageAcknowledgement}
	if s.BridgeReimageRetirement != "" {
		proof.Retirement, err = readRebuildInput(s.BridgeReimageRetirement, true)
		if err != nil {
			return nil, err
		}
	}
	fleet, err := readRebuildInput(s.BridgeReimageFleet, true)
	if err != nil {
		return nil, err
	}
	proof.Fleet, err = normalizeBridgeReimageFleet(fleet)
	if err != nil {
		return nil, err
	}
	for _, item := range []struct {
		path string
		out  *[]byte
	}{
		{s.BridgeReimageConfig, &proof.OldConfig},
		{filepath.Join(s.BridgeReimageArchive, "source-spec.original.json"), &proof.SourceSpec},
		{filepath.Join(s.BridgeReimageArchive, "legacy-journal.json"), &proof.LegacyJournal},
	} {
		*item.out, err = readRebuildInput(item.path, true)
		if err != nil {
			return nil, err
		}
	}
	var prior recoveryInputSources
	if decodeRetainedReconcile(proof.SourceSpec, &prior) != nil || prior.BridgeReimageConfig != "" || prior.BridgeReimageArchive != "" ||
		prior.BridgeReimageFleet != "" ||
		prior.BridgeReimageRetirement != "" {
		return nil, errors.New("bridge_reimage_prior_source_invalid")
	}
	prior.LegacyJournal = filepath.Join(s.BridgeReimageArchive, "legacy-journal.json")
	destination := filepath.Join(
		"/var/lib/ultra-ansible/operator-inputs",
		"manual-"+reimageJournalString(j, "commit")+"-"+reimageJournalString(j, "remote_attempt"),
		"preparation",
	)
	snapshot, _, err := recoveryInputExportPlan(
		prior,
		filepath.Join(s.BridgeReimageArchive, "known_hosts"),
		destination,
		reimageJournalString(j, "manifest_sha256"),
	)
	if err != nil {
		return nil, err
	}
	proof.Descriptor, err = json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	if err = validateRecoveryBridgeReimage(proof, journal, in); err != nil {
		return nil, err
	}
	// Match the old successful fleet evidence and exact transport target scope.
	p, err := installplan.LoadConfig(s.OriginalConfig)
	if err != nil {
		return nil, err
	}
	priorPlan, err := installplan.LoadLifecycleConfig(s.BridgeReimageConfig)
	if err != nil || len(priorPlan.Exits) != 1 || len(p.Exits) != 1 ||
		priorPlan.Bridge.SSHHost != p.Bridge.SSHHost || priorPlan.Bridge.Address != p.Bridge.Address ||
		priorPlan.Database.PrimaryHost != p.Database.PrimaryHost || priorPlan.Database.Name != p.Database.Name ||
		priorPlan.Exits[0].SSHHost != p.Exits[0].SSHHost || priorPlan.Exits[0].DialAddr != p.Exits[0].DialAddr || priorPlan.Exits[0].Port != p.Exits[0].Port {
		return nil, errors.New("bridge_reimage_historical_static_scope_changed")
	}
	old, evidence, err := loadRetainedBridgeSource(filepath.Join(s.BridgeReimageArchive, "source-spec.original.json"), p)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(evidence)
	if digestSHA256(raw) != in.RetainedExit.SourceSHA256 || old.Primary != in.Primary {
		return nil, errors.New("bridge_reimage_preserved_source_changed")
	}
	return proof, nil
}

func closeRecoveryBridgeReimage(ctx context.Context, r recoveryPreparationRequest) error {
	if err := verifyRecoveryPreparationPhase(ctx, "origins_sealed", r); err != nil {
		return err
	}
	in, err := validateRecoveryPreparationRequest(r)
	if err != nil {
		return err
	}
	if err = verifyRecoveryPreparationPrimary(ctx, r, in.retained); err != nil {
		return err
	}
	value := map[string]any{
		"protocol":            "ultra-bridge-reimage-supersession-v1",
		"result":              "superseded-by-bridge-reimage",
		"request_sha256":      r.digest(),
		"journal_sha256":      r.LegacyJournalSHA256,
		"bridge_fence_sha256": r.RetainedFenceSHA256,
		"exit_fence_sha256":   in.retained.RetainedExit.FenceSHA256,
	}
	raw, _ := json.Marshal(value)
	return withBridgeReimageFleet(ctx, r, in, func() error {
		return publishRetainedReconcile(filepath.Join(r.StateDirectory, "bridge-reimage-supersession.json"), raw)
	})
}

func verifyRecoveryBridgeReimageClosure(r recoveryPreparationRequest) error {
	in, err := validateRecoveryPreparationRequest(r)
	if err != nil {
		return err
	}
	raw, err := readRebuildInput(filepath.Join(r.StateDirectory, "bridge-reimage-supersession.json"), true)
	var got map[string]any
	want := map[string]any{
		"protocol":            "ultra-bridge-reimage-supersession-v1",
		"result":              "superseded-by-bridge-reimage",
		"request_sha256":      r.digest(),
		"journal_sha256":      r.LegacyJournalSHA256,
		"bridge_fence_sha256": r.RetainedFenceSHA256,
		"exit_fence_sha256":   in.retained.RetainedExit.FenceSHA256,
	}
	if err != nil || decodeRetainedReconcile(raw, &got) != nil || !reflect.DeepEqual(got, want) {
		return errors.New("bridge_reimage_supersession_unverified")
	}
	return nil
}
