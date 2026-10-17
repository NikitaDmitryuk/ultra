package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type forwardPriorCandidateKey struct{}
type forwardPriorCandidate struct{ Directory, Journal, SHA256 string }

func verifyForwardUnretired(root string, ids ...string) error {
	fail := errors.New("upgrade_forward_retirement_conflict")
	path := filepath.Join(root, "lifecycle-retired.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	}
	raw, err := readForwardEvidence(path)
	var ledger struct {
		Version int      `json:"version"`
		IDs     []string `json:"ids"`
		Handoff *struct {
			Old string `json:"old_id"`
			New string `json:"new_id"`
		} `json:"handoff"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&ledger) != nil || decoder.Decode(new(any)) != io.EOF || ledger.Version != 1 || ledger.IDs == nil {
		return fail
	}
	seen := map[string]bool{}
	for _, id := range ledger.IDs {
		if !regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(id) || seen[id] {
			return fail
		}
		seen[id] = true
	}
	if h := ledger.Handoff; h != nil {
		if !seen[h.Old] || h.Old == h.New ||
			!regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`).MatchString(h.New) {
			return fail
		}
		for _, id := range ids {
			if id == h.Old || id == h.New {
				return fail
			}
		}
	}
	for _, id := range ids {
		if seen[id] {
			return fail
		}
	}
	return nil
}

func verifyForwardPriorCandidate(
	proof forwardUpgradeJournal,
	old forwardOldOperation,
	root, directory string,
	prior forwardPriorCandidate,
) error {
	fail := errors.New("upgrade_forward_prior_candidate_unverified")
	if operatorPrivate(prior.Directory, true) != nil || prior.Directory == directory || prior.Directory == old.Directory ||
		!filepath.IsAbs(prior.Directory) ||
		filepath.Clean(prior.Directory) != prior.Directory ||
		filepath.Dir(prior.Directory) != root ||
		prior.Journal != filepath.Join(filepath.Dir(proof.Path), "forward-prior-operation.json") ||
		!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(prior.SHA256) {
		return fail
	}
	for _, path := range []string{prior.Directory, prior.Journal, proof.Path} {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || resolved != path {
			return fail
		}
	}
	raw, err := readForwardEvidence(prior.Journal)
	if err != nil || digestSHA256(raw) != prior.SHA256 {
		return fail
	}
	var journal struct {
		Schema      int    `json:"schema"`
		Commit      string `json:"commit"`
		Version     string `json:"version"`
		Attempt     string `json:"remote_attempt"`
		Stage       string `json:"stage"`
		Dispatched  bool   `json:"mutator_dispatched"`
		Forward     bool   `json:"forward_only"`
		ProofSHA    string `json:"forward_journal_sha256"`
		ConfigSHA   string `json:"staged_config_sha256"`
		ManifestSHA string `json:"manifest_sha256"`
	}
	if json.Unmarshal(raw, &journal) != nil || journal.Schema != 1 || !journal.Dispatched || !journal.Forward ||
		journal.Stage != "upgrade" ||
		journal.ProofSHA != proof.SHA256 ||
		!regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(journal.Commit) ||
		!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(journal.Attempt) ||
		prior.Directory != filepath.Join(root, "upgrade-"+journal.Version) {
		return fail
	}
	input := filepath.Join(root, "operator-inputs", "manual-"+journal.Commit+"-"+journal.Attempt)
	if resolved, err := filepath.EvalSymlinks(input); err != nil || resolved != input || operatorPrivate(input, true) != nil {
		return fail
	}
	config := filepath.Join(input, "install.config")
	configRaw, err := readForwardEvidence(config)
	if err != nil || digestSHA256(configRaw) != journal.ConfigSHA {
		return fail
	}
	plan, err := installplan.LoadConfig(config)
	release := filepath.Join(input, "release")
	if err != nil || installplan.ValidatePlan(plan) != nil || plan.Automation == nil || plan.Automation.Version != journal.Version ||
		plan.Automation.ReleaseDir != release ||
		matchOperatorPlan(prior.Directory, plan, release) != nil {
		return fail
	}
	if operatorPrivate(release, true) != nil {
		return fail
	}
	releaseEntries, err := os.ReadDir(release)
	if err != nil {
		return fail
	}
	for _, entry := range releaseEntries {
		if operatorPrivate(filepath.Join(release, entry.Name()), false) != nil {
			return fail
		}
	}
	priorManifest, err := verifyOperatorUpgradeRelease(
		release,
		journal.Commit,
		journal.Version,
		journal.ManifestSHA,
		filepath.Join(release, "ultra-install-linux-"+runtime.GOARCH),
	)
	if err != nil {
		return fail
	}
	modeRaw, err := readForwardEvidence(filepath.Join(prior.Directory, "execution-mode.json"))
	var mode frozenExecution
	if err != nil || json.Unmarshal(modeRaw, &mode) != nil || mode.Schema != 1 || !mode.Local || mode.Native ||
		mode.LockDirectory != root ||
		mode.OperatorDirectory != filepath.Join(root, "operator") ||
		mode.Target != plan.Bridge.SSHHost+"|"+plan.Bridge.Address {
		return fail
	}
	if verifyForwardUnretired(root, old.ID, lifecycleID(prior.Directory), lifecycleID(directory)) != nil {
		return fail
	}
	if verifyForwardApplying(root, old.ID) != nil {
		return fail
	}
	entries, err := os.ReadDir(prior.Directory)
	if err != nil {
		return fail
	}
	drains := 0
	failedBootstraps := 0
	hasIntent := false
	for _, entry := range entries {
		path := filepath.Join(prior.Directory, entry.Name())
		switch entry.Name() {
		case "runtime-use.json":
			if verifyForwardRuntimeUse(path, root, priorManifest) != nil {
				return fail
			}
		case "forward-handoff.json":
			if verifyForwardIntent(proof, old, root, prior.Directory) != nil {
				return fail
			}
			hasIntent = true
		case "execution-mode.json", "operator-plan.json":
			if _, err := readForwardEvidence(path); err != nil {
				return fail
			}
		default:
			if strings.HasPrefix(entry.Name(), "broker-bootstrap-") {
				variables, err := forwardBootstrapVariables(old, priorManifest, root, prior.Directory, release)
				if err != nil || verifyForwardFailedBootstrap(path, filepath.Join(release, "ultra-ansible.tar.gz"), old, variables) != nil {
					return fail
				}
				failedBootstraps++
				continue
			}
			if !strings.HasPrefix(entry.Name(), "handoff-drain-") || operatorPrivate(path, true) != nil {
				return fail
			}
			if _, err := forwardDrainIntent(proof, old, root, prior.Directory, path); err != nil {
				return fail
			}
			if err := verifyForwardDrainFiles(path, filepath.Join(release, "ultra-ansible.tar.gz")); err != nil {
				return fail
			}
			drains++
		}
	}
	// Verified drain stages can survive a failure before the handoff intent was
	// published. They authenticate retained artifacts, but do not replace the
	// caller's fresh census under the old OFD when that intent is absent.
	if hasIntent && (drains == 0 || failedBootstraps != 0) {
		return fail
	}
	return nil
}

// The prior release archive bounds every immutable exported source file; only
// the fixed controller protocol files, private workspace and empty temporary dirs may coexist.
func verifyForwardDrainFiles(stage, archive string) (result error) {
	fail := errors.New("upgrade_forward_prior_drain_files_invalid")
	allowed := map[string]bool{
		"request.json":          true,
		"job.json":              true,
		"receipt.json":          true,
		"result.json":           true,
		"inventory.json":        true,
		"inventory.yml":         true,
		"variables.json":        true,
		"variables.yml":         true,
		"bundle.retention.json": true,
		"diagnostic.json":       true,
		"execution.lock":        true,
	}
	entries, err := os.ReadDir(stage)
	if err != nil {
		return fail
	}
	for _, entry := range entries {
		path := filepath.Join(stage, entry.Name())
		if entry.Name() == "bundle" {
			if operatorPrivate(path, true) != nil {
				return fail
			}
			continue
		}
		if entry.Name() == ".ansible" {
			if verifyForwardControllerWorkspace(path) != nil {
				return fail
			}
			continue
		}
		if entry.Name() == "ansible-tmp" {
			children, err := os.ReadDir(path)
			if operatorPrivate(path, true) != nil || err != nil || len(children) != 0 {
				return fail
			}
			continue
		}
		if !allowed[entry.Name()] {
			return fail
		}
		if _, err := readForwardEvidence(path); err != nil {
			return fail
		}
	}
	file, err := os.Open(archive)
	if err != nil {
		return fail
	}
	defer func() {
		if err := file.Close(); err != nil && result == nil {
			result = fail
		}
	}()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return fail
	}
	defer func() {
		if err := gz.Close(); err != nil && result == nil {
			result = fail
		}
	}()
	tr := tar.NewReader(gz)
	expected := map[string]bool{".": true}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail
		}
		name := strings.TrimSuffix(header.Name, "/")
		if name == "" || !filepath.IsLocal(name) || filepath.Clean(name) != name || expected[name] {
			return fail
		}
		expected[name] = true
		path := filepath.Join(stage, "bundle", name)
		if header.Typeflag == tar.TypeDir {
			if operatorPrivate(path, true) != nil {
				return fail
			}
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 0 || header.Size > 1048576 {
			return fail
		}
		data, err := io.ReadAll(io.LimitReader(tr, 1048577))
		if err != nil || len(data) > 1048576 {
			return fail
		}
		existing, err := readForwardEvidence(path)
		if err != nil || !bytes.Equal(data, existing) {
			return fail
		}
	}
	err = filepath.WalkDir(filepath.Join(stage, "bundle"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return fail
		}
		name, err := filepath.Rel(filepath.Join(stage, "bundle"), path)
		if err != nil || !expected[filepath.ToSlash(name)] {
			return fail
		}
		return nil
	})
	if err != nil {
		return fail
	}
	return nil
}

// The workspace is generated under the controller's private HOME. It is not
// signed source or quiescence evidence; keep the existing lease/census gates.
func verifyForwardControllerWorkspace(directory string) error {
	fail := errors.New("upgrade_forward_controller_workspace_invalid")
	count := 0
	var total int64
	return filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return fail
		}
		info, err := entry.Info()
		if err != nil || (path == directory && !info.IsDir()) || operatorPrivate(path, info.IsDir()) != nil {
			return fail
		}
		count++
		if count > 20000 {
			return fail
		}
		if !info.IsDir() {
			if info.Size() > 2147483648 {
				return fail
			}
			total += info.Size()
			if total > 4294967296 {
				return fail
			}
		}
		return nil
	})
}

// Reconstruct the same complete request for a retained stage and a new dispatch.
func forwardBootstrapVariables(
	old forwardOldOperation,
	manifest *automationRelease,
	root, directory, release string,
) (map[string]any, error) {
	fail := errors.New("upgrade_forward_broker_bootstrap_unverified")
	installer, err := upgradeAsset(manifest, "ultra-install-linux-"+runtime.GOARCH)
	if err != nil {
		return nil, fail
	}
	offline, err := upgradeAsset(manifest, "ultra-ansible-runtime-linux-"+runtime.GOARCH+".tar.gz")
	if err != nil {
		return nil, fail
	}
	variables := map[string]any{
		"ultra_lock_directory":             root,
		"ultra_forward_old_id":             old.ID,
		"ultra_controller_directory":       managedControllerDirectory(manifest.Version),
		"ultra_install_source":             filepath.Join(release, installer.Name),
		"ultra_install_sha256":             installer.SHA,
		"ultra_controller_runtime_archive": filepath.Join(release, offline.Name),
		"ultra_controller_runtime_sha256":  offline.SHA,
	}

	identities, err := forwardBrokerVariables(old, manifest)
	if err != nil {
		return nil, err
	}
	for key, value := range identities {
		variables[key] = value
	}
	variables["ultra_forward_candidate_id"] = lifecycleID(directory)
	return variables, nil
}

// Only the exact read-only first guard may fail before a replacement candidate.
// Its diagnostic identifies the task, not the private module failure reason.
// The caller must still perform the fresh lease, census and live identity gates.
func verifyForwardFailedBootstrap(stage, archive string, old forwardOldOperation, variables map[string]any) error {
	fail := errors.New("upgrade_forward_prior_bootstrap_unverified")
	if operatorPrivate(old.Directory, true) != nil || operatorPrivate(filepath.Join(old.Directory, "activate"), true) != nil ||
		operatorPrivate(stage, true) != nil || verifyForwardDrainFiles(stage, archive) != nil {
		return fail
	}
	if _, err := os.Lstat(filepath.Join(stage, "result.json")); !os.IsNotExist(err) {
		return fail
	}
	// Bind the frozen fleet to the original activation request.
	oldRaw, err := readForwardEvidence(filepath.Join(old.Directory, "activate", "request.json"))
	var original struct {
		Inventory map[string]any `json:"inventory"`
	}
	if err != nil || json.Unmarshal(oldRaw, &original) != nil || original.Inventory == nil ||
		!reflect.DeepEqual(original.Inventory, old.Inventory) {
		return fail
	}
	expected, err := json.Marshal(map[string]any{"inventory": old.Inventory, "variables": variables})
	if err != nil {
		return fail
	}
	request, err := readForwardEvidence(filepath.Join(stage, "request.json"))
	if err != nil {
		return fail
	}
	if !bytes.Equal(request, expected) {
		// Before predecessor support, the same bootstrap request omitted only
		// this optional identity. Reconstruct that exact historical shape;
		// never normalize or discard fields from the retained request itself.
		legacyVariables := make(map[string]any, len(variables))
		for key, value := range variables {
			if key != "ultra_forward_previous_broker" {
				legacyVariables[key] = value
			}
		}
		legacyExpected, err := json.Marshal(map[string]any{"inventory": old.Inventory, "variables": legacyVariables})
		if err != nil || !bytes.Equal(request, legacyExpected) {
			return fail
		}
	}
	diagnostic := deployansible.Diagnostic{
		Stage: "Verify frozen broker identity and predecessor gate before replacement",
		Node:  "bridge",
		Code:  "task_failed",
	}
	decode := func(name string, value any) error {
		raw, err := readForwardEvidence(filepath.Join(stage, name))
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err != nil || decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
			return fail
		}
		return nil
	}
	var savedDiagnostic deployansible.Diagnostic
	if decode("diagnostic.json", &savedDiagnostic) != nil || savedDiagnostic != diagnostic {
		return fail
	}
	for _, name := range []string{"job.json", "receipt.json"} {
		var evidence struct {
			Schema     int                       `json:"schema_version"`
			Operation  string                    `json:"operation"`
			Request    string                    `json:"request_sha256"`
			Binary     string                    `json:"binary_sha256"`
			State      string                    `json:"state,omitempty"`
			Code       string                    `json:"code,omitempty"`
			ExitCode   *int                      `json:"exit_code,omitempty"`
			Diagnostic *deployansible.Diagnostic `json:"diagnostic,omitempty"`
			StartedAt  *int64                    `json:"started_at,omitempty"`
			FinishedAt *int64                    `json:"finished_at,omitempty"`
		}
		if decode(name, &evidence) != nil || evidence.Schema != 1 || evidence.Operation != "bootstrap-forward-broker" ||
			evidence.Request != digestSHA256(request) || evidence.Binary != digestSHA256(request) {
			return fail
		}
		if name == "receipt.json" {
			if evidence.State != "failed" || evidence.Code != "ansible_failed" || evidence.ExitCode == nil || *evidence.ExitCode != 2 ||
				evidence.Diagnostic == nil ||
				*evidence.Diagnostic != diagnostic {
				return fail
			}
		} else if evidence.State != "" || evidence.Code != "" || evidence.ExitCode != nil || evidence.Diagnostic != nil || evidence.StartedAt != nil || evidence.FinishedAt != nil {
			return fail
		}
	}
	return nil
}

func bootstrapForwardBroker(
	ctx context.Context,
	proof forwardUpgradeJournal,
	plan *installplan.InstallPlan,
	old forwardOldOperation,
	root, directory, python, executable string,
) error {
	fail := errors.New("upgrade_forward_broker_bootstrap_unverified")
	if plan.Automation == nil {
		return fail
	}
	a := plan.Automation
	manifest, err := verifyAutomationRelease(a.ReleaseDir, a.Version)
	if err != nil {
		return fail
	}
	variables, err := forwardBootstrapVariables(old, manifest, root, directory, a.ReleaseDir)
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		switch entry.Name() {
		case "runtime-use.json":
			if verifyForwardRuntimeUse(path, root, manifest) != nil {
				return fail
			}
		case "execution-mode.json", "operator-plan.json":
			if _, err := readForwardEvidence(path); err != nil {
				return fail
			}
		case "forward-handoff.json":
			if verifyForwardIntent(proof, old, root, directory) != nil {
				return fail
			}
		default:
			if strings.HasPrefix(entry.Name(), "broker-bootstrap-") {
				continue
			}
			if !strings.HasPrefix(entry.Name(), "handoff-drain-") {
				return fail
			}
			if _, err := forwardDrainIntent(proof, old, root, directory, path); err != nil {
				return fail
			}
			if verifyForwardDrainFiles(path, filepath.Join(a.ReleaseDir, "ultra-ansible.tar.gz")) != nil {
				return fail
			}
		}
	}
	if err := verifyForwardBrokerStages(directory, filepath.Join(a.ReleaseDir, "ultra-ansible.tar.gz"), old.Inventory, variables); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(directory, "broker-bootstrap-")
	if err != nil {
		return err
	}
	if err := os.Remove(stage); err != nil {
		return err
	}
	receipt, err := deployansible.RunLocal(ctx, "bootstrap-forward-broker", old.Inventory, variables, stage, python, executable)
	if err != nil {
		return err
	}
	if receipt.Result.Values["verified"] != true || receipt.Result.Values["old_id"] != old.ID ||
		receipt.Result.Values["controller_directory"] != managedControllerDirectory(a.Version) {
		return fail
	}
	return nil
}

func verifyForwardApplying(root, id string) error {
	raw, err := readForwardEvidence(filepath.Join(root, "lifecycle.json"))
	var state struct {
		ID    string `json:"id"`
		Phase string `json:"phase"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err != nil || decoder.Decode(&state) != nil || decoder.Decode(new(any)) != io.EOF || state.ID != id || state.Phase != "applying" {
		return errors.New("upgrade_forward_lifecycle_not_owned")
	}
	return nil
}

func verifyForwardBrokerStages(directory, archive string, inventory, variables map[string]any) error {
	fail := errors.New("upgrade_forward_broker_stage_unverified")
	expected, err := json.Marshal(map[string]any{"inventory": inventory, "variables": variables})
	if err != nil {
		return fail
	}
	digest := digestSHA256(expected)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fail
	}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "broker-bootstrap-") {
			continue
		}
		stage := filepath.Join(directory, entry.Name())
		if operatorPrivate(stage, true) != nil || verifyForwardDrainFiles(stage, archive) != nil {
			return fail
		}
		request, err := readForwardEvidence(filepath.Join(stage, "request.json"))
		if err != nil || !bytes.Equal(request, expected) {
			return fail
		}
		for _, name := range []string{"job.json", "receipt.json"} {
			raw, err := readForwardEvidence(filepath.Join(stage, name))
			var evidence struct {
				Schema    int    `json:"schema_version"`
				Operation string `json:"operation"`
				Request   string `json:"request_sha256"`
				Binary    string `json:"binary_sha256"`
				State     string `json:"state"`
			}
			if err != nil || json.Unmarshal(raw, &evidence) != nil || evidence.Schema != 1 ||
				evidence.Operation != "bootstrap-forward-broker" ||
				evidence.Request != digest ||
				evidence.Binary != digest {
				return fail
			}
			if name == "receipt.json" && evidence.State != "running" && evidence.State != "failed" && evidence.State != "succeeded" {
				return fail
			}
		}
	}
	return nil
}

// Type=simple reports started before the broker socket necessarily exists. Keep
// the old OFD through this bounded same-ID adoption retry; never reserve anew.
func resumeForwardBroker(ctx context.Context, root, id string, resume func(context.Context, string) error) error {
	deadline, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	for {
		if err := verifyForwardApplying(root, id); err != nil {
			return err
		}
		if err := resume(deadline, id); err == nil {
			return nil
		}
		select {
		case <-deadline.Done():
			return errors.New("upgrade_forward_broker_adoption_unverified")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func verifyForwardRuntimeUse(path, root string, manifest *automationRelease) error {
	fail := errors.New("upgrade_forward_runtime_use_unverified")
	asset, err := upgradeAsset(manifest, "ultra-ansible-runtime-linux-"+runtime.GOARCH+".tar.gz")
	if err != nil {
		return fail
	}
	raw, err := readForwardEvidence(path)
	if err != nil {
		return fail
	}
	var ref struct {
		Directory string `json:"runtime_directory"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&ref) != nil || decoder.Decode(new(any)) != io.EOF || ref.Directory != filepath.Join(root, "runtime-"+asset.SHA) {
		return fail
	}
	return nil
}
