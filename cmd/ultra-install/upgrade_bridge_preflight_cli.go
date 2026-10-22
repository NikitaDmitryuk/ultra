package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type bridgePreflightJournal struct {
	Schema            int    `json:"schema"`
	Commit            string `json:"commit"`
	Version           string `json:"version"`
	Adopt             bool   `json:"adopt"`
	Backup            string `json:"backup"`
	PreviousSHA       string `json:"previous_sha256"`
	ConfigSHA         string `json:"config_sha256"`
	Stage             string `json:"stage"`
	MutatorDispatched bool   `json:"mutator_dispatched"`
	TransportBinding  string `json:"transport_binding"`
	ManifestSHA       string `json:"manifest_sha256"`
	Attempt           string `json:"remote_attempt"`
	ProbeSHA          string `json:"probe_sha256"`
	ForwardOnly       bool   `json:"forward_only"`
	ForwardJournalSHA string `json:"forward_journal_sha256"`
	StagedConfigSHA   string `json:"staged_config_sha256"`
	Architecture      string `json:"remote_architecture"`
	SecretsSource     string `json:"secrets_source"`
	ConfigProjection  string `json:"config_projection"`
}

func parseBridgePreflightJournal(raw []byte) (bridgePreflightJournal, error) {
	var j bridgePreflightJournal
	var fields map[string]json.RawMessage
	commit, _ := new(big.Int).SetString(bridgePreflightCommit, 16)
	if len(raw) > 1048576 || json.Unmarshal(raw, &fields) != nil || len(fields) != 19 || decodeRetainedReconcile(raw, &j) != nil ||
		j.Schema != 1 || j.Commit != bridgePreflightCommit || j.Version != "v0.0."+commit.String() ||
		j.Adopt || j.Stage != "upgrade" || !j.MutatorDispatched || j.ForwardOnly || j.ForwardJournalSHA != "" ||
		j.SecretsSource != "installed-runtime" || j.ConfigProjection != "upgrade-v2" || j.Architecture != runtime.GOARCH ||
		!regexp.MustCompile(`^install\.config\.before-`+regexp.QuoteMeta(j.Version)+`-[0-9]+$`).MatchString(j.Backup) {
		return j, errors.New("bridge_preflight_journal_class_invalid")
	}
	for _, value := range []string{j.PreviousSHA, j.ConfigSHA, j.TransportBinding, j.ManifestSHA, j.Attempt, j.StagedConfigSHA} {
		if !runtimeHostValidDigest(value) {
			return j, errors.New("bridge_preflight_journal_binding_invalid")
		}
	}
	if j.ProbeSHA != "" && !runtimeHostValidDigest(j.ProbeSHA) {
		return j, errors.New("bridge_preflight_journal_binding_invalid")
	}
	return j, nil
}

type bridgePreflightReceipt struct {
	Protocol    string                       `json:"protocol"`
	Result      string                       `json:"result"`
	JournalSHA  string                       `json:"journal_sha256"`
	Commit      string                       `json:"commit"`
	Version     string                       `json:"version"`
	Attempt     string                       `json:"remote_attempt"`
	ConfigSHA   string                       `json:"staged_config_sha256"`
	ManifestSHA string                       `json:"manifest_sha256"`
	EvidenceSHA string                       `json:"evidence_sha256"`
	Admission   recoveryPreparationAdmission `json:"admission"`
}

func observeBridgePreflight(
	j bridgePreflightJournal,
	journalSHA string,
	admission recoveryPreparationAdmission,
) (bridgePreflightReceipt, error) {
	var receipt bridgePreflightReceipt
	root := "/var/lib/ultra-ansible"
	inputs := filepath.Join(root, "operator-inputs", "manual-"+j.Commit+"-"+j.Attempt)
	config := filepath.Join(inputs, "install.config")
	release := filepath.Join(inputs, "release")
	raw, err := readRebuildInput(config, true)
	if err != nil || digestSHA256(raw) != j.StagedConfigSHA {
		return receipt, errors.New("bridge_preflight_config_changed")
	}
	p, err := installplan.LoadLifecycleConfig(config)
	if err != nil {
		return receipt, errors.New("bridge_preflight_config_invalid")
	}
	if err = selectPlanSecrets(p, j.SecretsSource); err != nil || installplan.ValidatePlan(p) != nil ||
		p.Automation == nil || p.Automation.ReleaseDir != release || p.Automation.Version != j.Version {
		return receipt, errors.New("bridge_preflight_plan_changed")
	}
	manifest, err := verifyOperatorUpgradeRelease(release, j.Commit, j.Version, j.ManifestSHA,
		filepath.Join(release, "ultra-install-linux-"+j.Architecture))
	if err != nil {
		return receipt, errors.New("bridge_preflight_executed_bundle_unverified")
	}
	directory := filepath.Join(root, "upgrade-"+j.Version)
	if err = verifyBridgePreflightOperation(directory, p, release, manifest); err != nil {
		return receipt, err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return receipt, err
	}
	evidence := map[string]string{}
	for _, entry := range entries {
		raw, err = readForwardEvidence(filepath.Join(directory, entry.Name()))
		if err != nil {
			return receipt, err
		}
		evidence[entry.Name()] = digestSHA256(raw)
	}
	encoded, _ := json.Marshal(evidence)
	return bridgePreflightReceipt{"ultra-bridge-preflight-closure-v1", "preflight_failed_no_mutation", journalSHA,
		j.Commit, j.Version, j.Attempt, j.StagedConfigSHA, j.ManifestSHA, digestSHA256(encoded), admission}, nil
}

func runBridgePreflightProof(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("bridge-preflight-proof", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	encoded := fs.String("journal-base64", "", "exact private operator journal, base64 encoded")
	journalSHA := fs.String("journal-sha256", "", "pinned operator journal digest")
	nonce := fs.String("nonce", "", "operator challenge")
	if fs.Parse(args) != nil || fs.NArg() != 0 || !runtimeHostValidDigest(*journalSHA) || !runtimeHostValidDigest(*nonce) {
		return errors.New("bridge_preflight_arguments_invalid")
	}
	raw, err := base64.StdEncoding.DecodeString(*encoded)
	if err != nil || digestSHA256(raw) != *journalSHA {
		return errors.New("bridge_preflight_journal_changed")
	}
	j, err := parseBridgePreflightJournal(raw)
	if err != nil {
		return err
	}
	if os.Geteuid() != 0 || runtime.GOOS != "linux" {
		return errors.New("bridge_preflight_bridge_root_required")
	}
	admissionRaw, err := readRebuildInput(recoveryPreparationAdmissionPath, true)
	var admission recoveryPreparationAdmission
	if err != nil || decodeRetainedReconcile(admissionRaw, &admission) != nil || !admission.valid() {
		return errors.New("bridge_preflight_sealed_origins_required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	lease, err := openLocalRecoveryPreparationAdmission(ctx, admission, nil, false)
	if err != nil {
		return err
	}
	defer lease.close()
	receipt, err := observeBridgePreflight(j, *journalSHA, admission)
	if err != nil {
		return err
	}
	if err = json.NewEncoder(out).Encode(map[string]any{"nonce": *nonce, "receipt": receipt}); err != nil {
		return err
	}
	ack := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		ack <- scanner.Scan() && scanner.Text() == "ack "+*nonce
	}()
	select {
	case accepted := <-ack:
		if !accepted {
			return errors.New("bridge_preflight_ack_required")
		}
	case <-ctx.Done():
		return errors.New("bridge_preflight_ack_timeout")
	}
	if err = lease.recheck(); err != nil {
		return err
	}
	current, err := observeBridgePreflight(j, *journalSHA, admission)
	if err != nil || current != receipt {
		return errors.New("bridge_preflight_evidence_changed")
	}
	if err = publishBridgePreflightClosure(raw, j, *journalSHA, receipt); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "acknowledged "+*nonce)
	return err
}

// The coordinator has already frozen the journal in its immutable request; it
// uses the same source audit and protected publication as the operator adapter.
func closeRecoveryPreparationLegacy(ctx context.Context, r recoveryPreparationRequest) error {
	if r.BridgeReimage != nil {
		return closeRecoveryBridgeReimage(ctx, r)
	}
	in, err := validateRecoveryPreparationRequest(r)
	if err != nil {
		return err
	}
	if err = verifyRecoveryPreparationPhase(ctx, "origins_sealed", r); err != nil {
		return err
	}
	raw, err := readRebuildInput(r.LegacyJournalPath, true)
	if err != nil || digestSHA256(raw) != r.LegacyJournalSHA256 {
		return errors.New("bridge_preflight_journal_changed")
	}
	j, err := parseBridgePreflightJournal(raw)
	if err != nil {
		return err
	}
	lease, err := openLocalRecoveryPreparationAdmission(ctx, in.admission, nil, false)
	if err != nil {
		return err
	}
	defer lease.close()
	receipt, err := observeBridgePreflight(j, r.LegacyJournalSHA256, in.admission)
	if err != nil {
		return err
	}
	if err = lease.recheck(); err != nil {
		return err
	}
	if err = publishBridgePreflightClosure(raw, j, r.LegacyJournalSHA256, receipt); err != nil {
		return err
	}
	return verifyRecoveryPreparationLegacyClosure(r)
}

func publishBridgePreflightClosure(raw []byte, j bridgePreflightJournal, journalSHA string, receipt bridgePreflightReceipt) error {
	var err error
	directory := filepath.Join("/var/lib/ultra-ansible/preflight-closures", journalSHA)
	if err = ensurePrivateBootstrapDirectory(directory); err != nil {
		return err
	}
	if err = writeUpgradeInput(filepath.Join(directory, "operation.json"), raw); err != nil {
		return err
	}
	evidenceDirectory := filepath.Join(directory, "evidence")
	if err = ensurePrivateBootstrapDirectory(evidenceDirectory); err != nil {
		return err
	}
	originalDirectory := filepath.Join("/var/lib/ultra-ansible", "upgrade-"+j.Version)
	entries, err := os.ReadDir(originalDirectory)
	if err != nil {
		return err
	}
	evidence := map[string]string{}
	for _, entry := range entries {
		data, readErr := readForwardEvidence(filepath.Join(originalDirectory, entry.Name()))
		if readErr != nil {
			return readErr
		}
		evidence[entry.Name()] = digestSHA256(data)
		if err = writeUpgradeInput(filepath.Join(evidenceDirectory, entry.Name()), data); err != nil {
			return err
		}
	}
	evidenceRaw, _ := json.Marshal(evidence)
	if digestSHA256(evidenceRaw) != receipt.EvidenceSHA {
		return errors.New("bridge_preflight_evidence_changed")
	}
	encodedReceipt, _ := json.Marshal(receipt)
	if err = writeUpgradeInput(filepath.Join(directory, "receipt.json"), encodedReceipt); err != nil {
		return err
	}
	for _, parent := range []string{filepath.Dir(directory), filepath.Dir(filepath.Dir(directory))} {
		if err = syncUpgradeDirectory(parent); err != nil {
			return err
		}
	}

	return nil
}
