package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type forwardUpgradeJournalKey struct{}
type forwardUpgradeJournal struct{ Path, SHA256 string }

// The pinned operator transport supplies an archived journal and its digest;
// no caller chooses the old lifecycle UUID.
func withForwardUpgradeJournal(ctx context.Context, path, sha string) context.Context {
	return context.WithValue(ctx, forwardUpgradeJournalKey{}, forwardUpgradeJournal{path, sha})
}
func readForwardEvidence(path string) ([]byte, error) {
	if err := operatorPrivate(path, false); err != nil {
		return nil, errors.New("upgrade_forward_evidence_invalid")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("upgrade_forward_evidence_invalid")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close() //nolint:errcheck
	info, err := file.Stat()
	if err != nil {
		return nil, errors.New("upgrade_forward_evidence_invalid")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 1048576 {
		return nil, errors.New("upgrade_forward_evidence_invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 1048577))
	if err != nil || len(raw) > 1048576 {
		return nil, errors.New("upgrade_forward_evidence_invalid")
	}
	return raw, nil
}

type forwardOldOperation struct {
	Directory, ID string
	Inventory     map[string]any
}

func discoverForwardOldOperation(proof forwardUpgradeJournal, stateRoot string) (forwardOldOperation, error) {
	fail := errors.New("upgrade_forward_old_operation_unverified")
	var result forwardOldOperation
	digest := regexp.MustCompile(`^[a-f0-9]{64}$`)
	if !digest.MatchString(proof.SHA256) || !filepath.IsAbs(proof.Path) {
		return result, fail
	}
	raw, err := readForwardEvidence(proof.Path)
	if err != nil || digestSHA256(raw) != proof.SHA256 {
		return result, fail
	}
	var journal struct {
		Schema      int    `json:"schema"`
		Commit      string `json:"commit"`
		Version     string `json:"version"`
		Attempt     string `json:"remote_attempt"`
		Stage       string `json:"stage"`
		Dispatched  bool   `json:"mutator_dispatched"`
		ManifestSHA string `json:"manifest_sha256"`
		ConfigSHA   string `json:"staged_config_sha256"`
	}
	if json.Unmarshal(raw, &journal) != nil || journal.Schema != 1 || !journal.Dispatched || journal.Stage != "upgrade" ||
		!regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(journal.Commit) || !digest.MatchString(journal.Attempt) ||
		!digest.MatchString(journal.ManifestSHA) || !digest.MatchString(journal.ConfigSHA) {
		return result, fail
	}
	number, _ := new(big.Int).SetString(journal.Commit, 16)
	if journal.Version != "v0.0."+number.String() {
		return result, fail
	}
	directory := filepath.Join(stateRoot, "upgrade-"+journal.Version)
	if operatorPrivate(directory, true) != nil {
		return result, fail
	}
	input := filepath.Join(stateRoot, "operator-inputs", "manual-"+journal.Commit+"-"+journal.Attempt)
	config := filepath.Join(input, "install.config")
	configRaw, err := readForwardEvidence(config)
	if err != nil || digestSHA256(configRaw) != journal.ConfigSHA {
		return result, fail
	}
	plan, err := installplan.LoadConfig(config)
	release := filepath.Join(input, "release")
	if err != nil || installplan.ValidatePlan(plan) != nil || plan.Automation == nil || plan.Automation.Version != journal.Version || plan.Automation.ReleaseDir != release || matchOperatorPlan(directory, plan, release) != nil {
		return result, fail
	}
	requestRaw, err := readForwardEvidence(filepath.Join(directory, "activate", "request.json"))
	if err != nil {
		return result, fail
	}
	var request struct {
		Inventory map[string]any `json:"inventory"`
		Variables struct {
			ID          string            `json:"ultra_lifecycle_id"`
			ManifestSHA string            `json:"ultra_release_manifest_sha256"`
			Manifest    automationRelease `json:"ultra_release_manifest"`
		} `json:"variables"`
	}
	if json.Unmarshal(requestRaw, &request) != nil || request.Inventory == nil || request.Variables.ID != lifecycleID(directory) || request.Variables.ManifestSHA != journal.ManifestSHA || request.Variables.Manifest.SourceCommit != journal.Commit || request.Variables.Manifest.Version != journal.Version {
		return result, fail
	}
	for _, name := range []string{"job.json", "receipt.json"} {
		evidence, err := readForwardEvidence(filepath.Join(directory, "activate", name))
		var job struct {
			Schema     int    `json:"schema_version"`
			Operation  string `json:"operation"`
			RequestSHA string `json:"request_sha256"`
		}
		if err != nil || json.Unmarshal(evidence, &job) != nil || job.Schema != 1 || job.Operation != "upgrade" || job.RequestSHA != digestSHA256(requestRaw) {
			return result, fail
		}
	}
	all, ok := request.Inventory["all"].(map[string]any)
	if !ok {
		return result, fail
	}
	children, ok := all["children"].(map[string]any)
	if !ok {
		return result, fail
	}
	for _, group := range []string{"bridge", "exits"} {
		value, ok := children[group].(map[string]any)
		if !ok {
			return result, fail
		}
		hosts, ok := value["hosts"].(map[string]any)
		if !ok || len(hosts) == 0 || (group == "bridge" && len(hosts) != 1) {
			return result, fail
		}
	}
	return forwardOldOperation{directory, lifecycleID(directory), request.Inventory}, nil
}

// The caller already holds the common operator lock. Hold the old OFD through
// a fresh full-fleet census and durable old-to-new broker supersession.
func withForwardUpgradeHandoff(ctx context.Context, p *installplan.InstallPlan, lockDirectory, directory, python, executable string) (context.Context, func(), error) {
	proof, ok := ctx.Value(forwardUpgradeJournalKey{}).(forwardUpgradeJournal)
	if !ok || os.Geteuid() != 0 || lockDirectory != "/var/lib/ultra-ansible" || !localLifecycleBridge(p) {
		return ctx, nil, errors.New("upgrade_forward_handoff_requires_local_proof")
	}
	old, err := discoverForwardOldOperation(proof, lockDirectory)
	if err != nil || old.Directory == directory {
		return ctx, nil, errors.New("upgrade_forward_old_operation_unverified")
	}
	socket := os.Getenv("ULTRA_ANSIBLE_SOCKET")
	if socket == "" {
		socket = "/run/ultra-ansible/controller.sock"
	}
	client := deployansible.Client{Socket: socket}
	return forwardUpgradeHandoff(ctx, proof, old, lockDirectory, directory, python, executable, forwardHandoffDeps{
		attach: client.WithLifecycleOperationLock, run: deployansible.RunLocal, supersede: client.SupersedeLifecycle,
		prepare: func(leased context.Context) error {
			if prior, ok := ctx.Value(forwardPriorCandidateKey{}).(forwardPriorCandidate); ok {
				if p.Automation == nil || proof.Path != filepath.Join(filepath.Dir(p.Automation.ReleaseDir), "forward-operation.json") || prior.Journal != filepath.Join(filepath.Dir(p.Automation.ReleaseDir), "forward-prior-operation.json") {
					return errors.New("upgrade_forward_prior_input_location_invalid")
				}
				if err := verifyForwardPriorCandidate(proof, old, lockDirectory, directory, prior); err != nil {
					return err
				}

				_, intentErr := os.Lstat(filepath.Join(prior.Directory, "forward-handoff.json"))
				if intentErr != nil && !os.IsNotExist(intentErr) {
					return intentErr
				}
				return prepareForwardRecovery(leased, os.IsNotExist(intentErr),
					func(censusCtx context.Context) error {
						_, err := runForwardCensus(censusCtx, proof, old, lockDirectory, directory, python, executable, deployansible.RunLocal)
						return err
					},
					func(bootstrapCtx context.Context) error {
						return bootstrapForwardBroker(bootstrapCtx, proof, p, old, lockDirectory, directory, python, executable)
					},
					func(adoptCtx context.Context) error {
						return resumeForwardBroker(adoptCtx, lockDirectory, old.ID, client.ResumeLifecycleWithOperationLock)
					},
				)
			}
			return nil
		},
	})
}

type forwardHandoffDeps struct {
	prepare   func(context.Context) error
	attach    func(context.Context, string, string) (context.Context, func(), error)
	run       func(context.Context, string, map[string]any, map[string]any, string, string, string) (deployansible.Receipt, error)
	supersede func(context.Context, string, string) error
}

type forwardHandoffIntent struct {
	Schema     int    `json:"schema"`
	ProofSHA   string `json:"proof_sha256"`
	OldID      string `json:"old_id"`
	NewID      string `json:"new_id"`
	Stage      string `json:"drain_directory"`
	RequestSHA string `json:"request_sha256"`
	JobSHA     string `json:"job_sha256"`
	ReceiptSHA string `json:"receipt_sha256"`
	ResultSHA  string `json:"result_sha256"`
}

func forwardDrainVariables(lockDirectory, oldID, newID string) map[string]any {
	return map[string]any{"ultra_lock_directory": lockDirectory, "ultra_forward_old_id": oldID, "ultra_lifecycle_id": newID}
}

// Hash every durable component after checking the fixed operation's exact
// request, job identity, successful receipt and complete fleet output.
func forwardDrainIntent(proof forwardUpgradeJournal, old forwardOldOperation, lockDirectory, directory, stage string) (forwardHandoffIntent, error) {
	fail := errors.New("upgrade_forward_saved_drain_unverified")
	var intent forwardHandoffIntent
	if !filepath.IsAbs(stage) || filepath.Clean(stage) != stage || filepath.Dir(stage) != directory || !strings.HasPrefix(filepath.Base(stage), "handoff-drain-") || operatorPrivate(stage, true) != nil {
		return intent, fail
	}
	expected, err := json.Marshal(map[string]any{"inventory": old.Inventory, "variables": forwardDrainVariables(lockDirectory, old.ID, lifecycleID(directory))})
	if err != nil {
		return intent, fail
	}
	request, err := readForwardEvidence(filepath.Join(stage, "request.json"))
	if err != nil || !bytes.Equal(request, expected) {
		return intent, fail
	}
	jobRaw, err := readForwardEvidence(filepath.Join(stage, "job.json"))
	if err != nil {
		return intent, fail
	}
	receiptRaw, err := readForwardEvidence(filepath.Join(stage, "receipt.json"))
	if err != nil {
		return intent, fail
	}
	outputRaw, err := readForwardEvidence(filepath.Join(stage, "result.json"))
	if err != nil {
		return intent, fail
	}
	digest := digestSHA256(request)
	var job, receipt struct {
		Schema     int            `json:"schema_version"`
		Operation  string         `json:"operation"`
		RequestSHA string         `json:"request_sha256"`
		BinarySHA  string         `json:"binary_sha256"`
		State      string         `json:"state"`
		Code       string         `json:"code"`
		Result     map[string]any `json:"result"`
	}
	if json.Unmarshal(jobRaw, &job) != nil || json.Unmarshal(receiptRaw, &receipt) != nil {
		return intent, fail
	}
	for _, evidence := range []struct {
		schema                     int
		operation, request, binary string
	}{{job.Schema, job.Operation, job.RequestSHA, job.BinarySHA}, {receipt.Schema, receipt.Operation, receipt.RequestSHA, receipt.BinarySHA}} {
		if evidence.schema != 1 || evidence.operation != "drain-upgrade-workers" || evidence.request != digest || evidence.binary != digest {
			return intent, fail
		}
	}
	expectedResult := map[string]any{"verified": true, "old_id": old.ID, "new_id": lifecycleID(directory)}
	resultJSON, _ := json.Marshal(receipt.Result)
	expectedJSON, _ := json.Marshal(expectedResult)
	var output map[string]any
	if json.Unmarshal(outputRaw, &output) != nil || receipt.State != "succeeded" || receipt.Code != "" || !bytes.Equal(resultJSON, expectedJSON) {
		return intent, fail
	}
	outputJSON, _ := json.Marshal(output)
	if !bytes.Equal(outputJSON, expectedJSON) {
		return intent, fail
	}
	return forwardHandoffIntent{1, proof.SHA256, old.ID, lifecycleID(directory), stage, digest, digestSHA256(jobRaw), digestSHA256(receiptRaw), digestSHA256(outputRaw)}, nil
}

func loadForwardIntent(path string) (forwardHandoffIntent, error) {
	var intent forwardHandoffIntent
	raw, err := readForwardEvidence(path)
	if err != nil {
		return intent, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&intent) != nil || decoder.Decode(new(any)) != io.EOF || intent.Schema != 1 {
		return intent, errors.New("upgrade_forward_intent_invalid")
	}
	return intent, nil
}

func verifyForwardIntent(proof forwardUpgradeJournal, old forwardOldOperation, lockDirectory, directory string) error {
	intent, err := loadForwardIntent(filepath.Join(directory, "forward-handoff.json"))
	if err != nil {
		return err
	}
	current, err := forwardDrainIntent(proof, old, lockDirectory, directory, intent.Stage)
	if err != nil || intent != current {
		return errors.New("upgrade_forward_intent_changed")
	}
	return nil
}

func saveForwardIntent(directory string, intent forwardHandoffIntent) error {
	if operatorPrivate(directory, true) != nil {
		return errors.New("upgrade_forward_intent_directory_invalid")
	}
	path := filepath.Join(directory, "forward-handoff.json")
	if _, err := os.Lstat(path); err == nil {
		if _, err = readForwardEvidence(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	raw, err := json.Marshal(intent)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(directory, ".forward-handoff-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name) //nolint:errcheck
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(raw)
	}
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	return syncUpgradeDirectory(directory)
}

func verifyForwardRetirement(lockDirectory, oldID, newID string) error {
	raw, err := readForwardEvidence(filepath.Join(lockDirectory, "lifecycle-retired.json"))
	var ledger struct {
		Version int      `json:"version"`
		IDs     []string `json:"ids"`
		Handoff *struct {
			OldID string `json:"old_id"`
			NewID string `json:"new_id"`
		} `json:"handoff"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&ledger) != nil || decoder.Decode(new(any)) != io.EOF || ledger.Version != 1 || ledger.Handoff == nil || ledger.Handoff.OldID != oldID || ledger.Handoff.NewID != newID {
		return errors.New("upgrade_forward_retirement_unverified")
	}
	seen := map[string]bool{}
	for _, id := range ledger.IDs {
		if !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(id) || seen[id] {
			return errors.New("upgrade_forward_retirement_unverified")
		}
		seen[id] = true
	}
	if !seen[oldID] || seen[newID] {
		return errors.New("upgrade_forward_retirement_unverified")
	}
	return nil
}

func forwardUpgradeHandoff(ctx context.Context, proof forwardUpgradeJournal, old forwardOldOperation, lockDirectory, directory, python, executable string, deps forwardHandoffDeps) (context.Context, func(), error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || operatorPrivate(directory, true) != nil || operatorPrivate(lockDirectory, true) != nil {
		return ctx, nil, errors.New("upgrade_forward_handoff_directory_invalid")
	}
	stateRaw, err := readForwardEvidence(filepath.Join(lockDirectory, "lifecycle.json"))
	var state struct{ ID, Phase string }
	newID := lifecycleID(directory)
	if err != nil || json.Unmarshal(stateRaw, &state) != nil || state.Phase != "applying" || (state.ID != old.ID && state.ID != newID) {
		return ctx, nil, errors.New("upgrade_forward_lifecycle_not_owned")
	}
	intentPath := filepath.Join(directory, "forward-handoff.json")
	if state.ID == newID {
		if err = verifyForwardIntent(proof, old, lockDirectory, directory); err != nil {
			return ctx, nil, err
		}
		if err = verifyForwardRetirement(lockDirectory, old.ID, newID); err != nil {
			return ctx, nil, err
		}
		// The prior supersede committed. Never attach the retired ID or replay its
		// dispatch; the persisted census and broker write-ahead journal prove it.
		return deps.attach(ctx, lockDirectory, newID)
	}
	if _, err = os.Lstat(intentPath); err == nil {
		if err = verifyForwardIntent(proof, old, lockDirectory, directory); err != nil {
			return ctx, nil, err
		}
	} else if !os.IsNotExist(err) {
		return ctx, nil, err
	}
	leased, release, err := deps.attach(ctx, lockDirectory, old.ID)
	if err != nil {
		return ctx, nil, err
	}
	success := false
	defer func() {
		if !success {
			release()
		}
	}()
	if err = verifyForwardApplying(lockDirectory, old.ID); err != nil {
		return ctx, nil, err
	}
	if err = verifyForwardUnretired(lockDirectory, old.ID, newID); err != nil {
		return ctx, nil, err
	}
	if _, activationErr := os.Lstat(filepath.Join(directory, "activate")); !os.IsNotExist(activationErr) {
		return ctx, nil, errors.New("upgrade_forward_activation_started")
	}
	// Recovery may replace the broker only while the attached predecessor OFD
	// remains live. It must adopt that descriptor before the final handoff census.
	if deps.prepare != nil {
		if err = deps.prepare(leased); err != nil {
			return ctx, nil, err
		}
	}
	if err = verifyForwardUnretired(lockDirectory, old.ID, newID); err != nil {
		return ctx, nil, err
	}
	if err = verifyForwardApplying(lockDirectory, old.ID); err != nil {
		return ctx, nil, err
	}
	intent, err := runForwardCensus(leased, proof, old, lockDirectory, directory, python, executable, deps.run)
	if err != nil {
		return ctx, nil, err
	}
	if err = saveForwardIntent(directory, intent); err != nil {
		return ctx, nil, err
	}
	if err = deps.supersede(leased, old.ID, newID); err != nil {
		return ctx, nil, err
	}
	success = true
	return leased, release, nil
}

// A candidate with no saved census cannot authorize even a broker replacement.
// Prove the frozen fleet quiescent first, then bootstrap/adopt; the caller still
// repeats the census afterwards before publishing its new handoff intent.
func prepareForwardRecovery(ctx context.Context, requireCensus bool, census, bootstrap, adopt func(context.Context) error) error {
	if requireCensus {
		if err := census(ctx); err != nil {
			return err
		}
	}
	if err := bootstrap(ctx); err != nil {
		return err
	}
	return adopt(ctx)
}

func runForwardCensus(ctx context.Context, proof forwardUpgradeJournal, old forwardOldOperation, lockDirectory, directory, python, executable string, run func(context.Context, string, map[string]any, map[string]any, string, string, string) (deployansible.Receipt, error)) (forwardHandoffIntent, error) {
	stage, err := os.MkdirTemp(directory, "handoff-drain-")
	if err != nil {
		return forwardHandoffIntent{}, err
	}
	if err = os.Remove(stage); err != nil {
		return forwardHandoffIntent{}, err
	}
	receipt, err := run(ctx, "drain-upgrade-workers", old.Inventory, forwardDrainVariables(lockDirectory, old.ID, lifecycleID(directory)), stage, python, executable)
	if err != nil {
		return forwardHandoffIntent{}, err
	}
	if receipt.Result.Values["verified"] != true || receipt.Result.Values["old_id"] != old.ID || receipt.Result.Values["new_id"] != lifecycleID(directory) {
		return forwardHandoffIntent{}, errors.New("upgrade_forward_fleet_drain_unverified")
	}
	intent, err := forwardDrainIntent(proof, old, lockDirectory, directory, stage)
	if err != nil {
		return forwardHandoffIntent{}, err
	}

	return intent, nil
}
