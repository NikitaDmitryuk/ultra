package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"syscall"
)

const operatorCompletionFile = "operation.completed.json"

type operatorCompletion struct {
	Schema          int                       `json:"schema"`
	Path            string                    `json:"path"`
	ID              string                    `json:"operation_id"`
	Kind            string                    `json:"kind"`
	Version         string                    `json:"version"`
	Commit          string                    `json:"source_commit"`
	ManifestSHA     string                    `json:"manifest_sha256"`
	Metadata        map[string]string         `json:"metadata"`
	Payloads        map[string]map[string]any `json:"payloads"`
	BundleReceipts  map[string]string         `json:"bundle_receipts,omitempty"`
	RetainedUnknown []string                  `json:"retained_unknown,omitempty"`
}

func operatorPrivate(path string, directory bool) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("operator_retention_symlink")
		}
		if current == path {
			owner, ok := info.Sys().(*syscall.Stat_t)
			if !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
				return errors.New("operator_retention_private_required")
			}
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	return nil
}

// Metadata survives collection, so cached completion never reads deleted inputs.
// Include every JSON input, generation and child receipt; added jobs invalidate it.
func operatorMetadata(directory string) (map[string]string, error) {
	if err := operatorPrivate(directory, true); err != nil {
		return nil, err
	}
	result := map[string]string{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == directory {
			return nil
		}
		if entry.IsDir() && (entry.Name() == "bundle" || entry.Name() == "recovery-bundle" || entry.Name() == "ansible-tmp" || entry.Name() == "__pycache__") {
			return filepath.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("operator_retention_symlink")
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || entry.Name() == operatorCompletionFile {
			return nil
		}
		if err := operatorPrivate(path, false); err != nil {
			return err
		}
		info, err := os.Stat(path)
		if err != nil || info.Size() > 4<<20 {
			return errors.New("operator_retention_metadata_invalid")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !json.Valid(raw) {
			return errors.New("operator_retention_metadata_invalid")
		}
		relative, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(raw)
		result[filepath.ToSlash(relative)] = hex.EncodeToString(sum[:])
		if entry.Name() == "job.json" {
			var job struct {
				Schema     int    `json:"schema_version"`
				RequestSHA string `json:"request_sha256"`
			}
			var receipt struct {
				State      string `json:"state"`
				RequestSHA string `json:"request_sha256"`
			}
			receiptPath := filepath.Join(filepath.Dir(path), "receipt.json")
			if err := operatorPrivate(receiptPath, false); err != nil {
				return err
			}
			receiptRaw, err := os.ReadFile(receiptPath)
			if err != nil || json.Unmarshal(raw, &job) != nil || json.Unmarshal(receiptRaw, &receipt) != nil || job.Schema != 1 || (receipt.State != "succeeded" && receipt.State != "failed" && !retiredOperatorObservationValid(directory, filepath.Dir(path))) || receipt.RequestSHA != job.RequestSHA {
				return errors.New("operator_retention_stage_incomplete")
			}
			requestPath := filepath.Join(filepath.Dir(path), "request.json")
			if err := operatorPrivate(requestPath, false); err != nil {
				return err
			}
			requestSHA, err := sourceSHA(requestPath)
			if err != nil || requestSHA != job.RequestSHA {
				return errors.New("operator_retention_stage_identity_changed")
			}
		}
		return nil
	})
	return result, err
}

// sealCompletedOperatorOperation is called only after the entire successful
// transaction, release finalization and cleanup have durably finished. Failed
// transactions remain resumable and cannot acquire this success receipt.
func sealCompletedOperatorOperation(directory, kind string, manifest *automationRelease, manifestSHA string) error {
	if manifest == nil || manifest.Version == "" || len(manifest.SourceCommit) != 40 || len(manifestSHA) != 64 {
		return errors.New("operator_retention_release_identity_required")
	}
	if err := operatorWinningChain(directory, kind, manifest, manifestSHA); err != nil {
		return err
	}
	if kind == "bootstrap" {
		if err := proveBootstrapEmergencySources(directory, manifest, manifestSHA); err != nil {
			return err
		}
	}
	if err := retireInterruptedOperatorObservations(directory, kind, manifest, manifestSHA); err != nil {
		return err
	}
	metadata, err := operatorMetadata(directory)
	if err != nil {
		return err
	}
	if metadata["inventory.frozen.json"] == "" || metadata["execution-mode.json"] == "" {
		return errors.New("operator_retention_frozen_identity_required")
	}
	payloads := map[string]map[string]any{}
	unknown := []string{}
	bundleReceipts := map[string]string{}
	err = filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if (entry.IsDir() && (entry.Name() == "bundle" || entry.Name() == "recovery-bundle" || (entry.Name() == "tools" && filepath.Base(filepath.Dir(path)) == "automation-sources"))) || (entry.Name() == "bootstrap_plan.py" && filepath.Base(filepath.Dir(path)) == "automation-sources") {
			var contents map[string]any
			if entry.Name() == "bundle" {
				proofPath := filepath.Join(filepath.Dir(path), "bundle.retention.json")
				if err := operatorPrivate(proofPath, false); err != nil {
					if os.IsNotExist(err) {
						unknown = append(unknown, path)
						return filepath.SkipDir
					}
					return err
				}
				raw, err := os.ReadFile(proofPath)
				if err != nil {
					return err
				}
				var proof struct {
					Schema    int               `json:"schema"`
					Identity  map[string]string `json:"identity"`
					Path      string            `json:"path"`
					Inventory map[string]any    `json:"inventory"`
				}
				requestSHA, hashErr := sourceSHA(filepath.Join(filepath.Dir(path), "request.json"))
				if json.Unmarshal(raw, &proof) != nil || proof.Schema != 1 || proof.Path != path || proof.Inventory == nil || hashErr != nil || proof.Identity["request_sha256"] != requestSHA {
					return errors.New("operator_retention_bundle_identity_invalid")
				}
				contents = normalizeOperatorBundleInventory(proof.Inventory)
			} else {
				contents, err = operatorPayloadContents(path)
				if err != nil {
					return err
				}
			}
			relative, _ := filepath.Rel(directory, path)
			if entry.Name() == "bundle" {
				bundleReceipts[filepath.ToSlash(relative)] = filepath.ToSlash(filepath.Join(filepath.Dir(relative), "bundle.retention.json"))
			} else {
				payloads[filepath.ToSlash(relative)] = contents
			}
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() && (entry.Name() == "ansible-tmp" || entry.Name() == "__pycache__") {
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return err
	}
	state := operatorCompletion{Schema: 1, Path: directory, ID: lifecycleID(directory), Kind: kind, Version: manifest.Version, Commit: manifest.SourceCommit, ManifestSHA: manifestSHA, Metadata: metadata, Payloads: payloads, RetainedUnknown: unknown, BundleReceipts: bundleReceipts}
	if len(unknown) > 0 {
		fmt.Fprintln(os.Stderr, "operator_retention_retained_unknown:", len(unknown), "legacy payloads")
	}
	raw, err := json.Marshal(state)
	if err != nil {
		return err
	}
	if len(raw) > 4<<20 {
		return errors.New("operator_retention_completion_too_large")
	}
	return writeUpgradeInput(filepath.Join(directory, operatorCompletionFile), raw)
}

func completedOperatorOperation(directory, kind, version string) (bool, error) {
	path := filepath.Join(directory, operatorCompletionFile)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return false, nil
	}
	if err := operatorPrivate(path, false); err != nil {
		return true, err
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 4<<20 {
		return true, errors.New("operator_retention_completion_invalid")
	}
	var state operatorCompletion
	if json.Unmarshal(raw, &state) != nil || state.Schema != 1 || state.Path != directory || state.ID != lifecycleID(directory) || state.Kind != kind || (version != "" && state.Version != version) || len(state.Commit) != 40 || len(state.ManifestSHA) != 64 {
		return true, errors.New("operator_retention_completion_invalid")
	}
	manifest := &automationRelease{Version: state.Version, SourceCommit: state.Commit}
	if err := operatorWinningChain(directory, kind, manifest, state.ManifestSHA); err != nil {
		return true, err
	}
	metadata, err := operatorMetadata(directory)
	if err != nil {
		return true, err
	}
	if !reflect.DeepEqual(metadata, state.Metadata) {
		return true, errors.New("operator_retention_completion_changed")
	}
	return true, nil
}

// Recovery tools contain regular files only. The full inventory is captured by
// the whole transaction seal, after extraction checked every archive member.
func operatorPayloadInventory(directory string) (map[string]any, error) {
	if err := operatorPrivate(directory, true); err != nil {
		return nil, err
	}
	contents := map[string]any{}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == directory {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("operator_retention_payload_invalid")
		}
		relative, _ := filepath.Rel(directory, path)
		if entry.IsDir() {
			if entry.Name() == "__pycache__" {
				return nil
			}
			contents[filepath.ToSlash(relative)] = []any{"directory", uint32(info.Mode().Perm())}
			return nil
		}
		if !info.Mode().IsRegular() || owner.Nlink != 1 {
			return errors.New("operator_retention_payload_invalid")
		}
		if filepath.Base(filepath.Dir(path)) == "__pycache__" {
			match := regexp.MustCompile(`^(.+)\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc$`).FindStringSubmatch(entry.Name())
			if len(match) == 2 {
				source := filepath.Join(filepath.Dir(filepath.Dir(path)), match[1]+".py")
				if info, err := os.Lstat(source); err == nil && info.Mode().IsRegular() {
					return nil
				}
			}
		}
		checksum, err := sourceSHA(path)
		if err != nil {
			return err
		}
		contents[filepath.ToSlash(relative)] = []any{"file", checksum, uint32(info.Mode().Perm())}
		return nil
	})
	return contents, err
}

// Runtime routing is derived at execution time and is excluded from the caller
// plan identity; every requested deployment field and release path remain bound.
func operatorPlanDigest(p *installplan.InstallPlan, releaseDir string) (string, error) {
	clone := *p
	clone.ControllerLocal = nil
	clone.ControllerLocalTarget = ""
	raw, err := json.Marshal(struct {
		Plan    *installplan.InstallPlan `json:"plan"`
		Release string                   `json:"release"`
	}{&clone, releaseDir})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func freezeOperatorPlan(directory string, p *installplan.InstallPlan, releaseDir string) error {
	hash, err := operatorPlanDigest(p, releaseDir)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(map[string]string{"plan_sha256": hash})
	return writeUpgradeInput(filepath.Join(directory, "operator-plan.json"), raw)
}
func matchOperatorPlan(directory string, p *installplan.InstallPlan, releaseDir string) error {
	hash, err := operatorPlanDigest(p, releaseDir)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "operator-plan.json")
	if err := operatorPrivate(path, false); err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	var identity map[string]string
	if err != nil || json.Unmarshal(raw, &identity) != nil || identity["plan_sha256"] != hash {
		return errors.New("operator_retention_completed_plan_changed")
	}
	return nil
}

// External lock survives cache deletion and recreation; users hold shared leases
// through their final subprocess, preparation and collection hold exclusive ones.
func operatorRuntimeLock(root string, exclusive bool) (func(), error) {
	lockRoot := filepath.Join(filepath.Dir(root), "runtime-retention")
	if err := ensurePrivateBootstrapDirectory(lockRoot); err != nil {
		return nil, err
	}
	path := filepath.Join(lockRoot, filepath.Base(root)+".lock")
	if info, err := os.Lstat(path); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("operator_runtime_lock_invalid")
	}
	lock, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX | syscall.LOCK_NB
	}
	if err = syscall.Flock(int(lock.Fd()), mode); err != nil {
		_ = lock.Close()
		return nil, err
	}
	return func() { _ = lock.Close() }, nil
}
func pinOperatorRuntime(executable string) (func(), error) {
	root := filepath.Dir(filepath.Dir(filepath.Dir(executable)))
	if !regexp.MustCompile(`^runtime-[a-f0-9]{64}$`).MatchString(filepath.Base(root)) {
		return func() {}, nil
	}
	release, err := operatorRuntimeLock(root, false)
	if err != nil {
		return nil, err
	}
	if err = operatorPrivate(root, true); err != nil {
		release()
		return nil, err
	}
	if _, err = os.Stat(executable); err != nil {
		release()
		return nil, err
	}
	return release, nil
}

func operatorRuntimeInventory(directory string) (map[string]any, error) {
	contents := map[string]any{}
	if err := operatorPrivate(directory, true); err != nil {
		return nil, err
	}
	err := filepath.WalkDir(directory, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == directory {
			return nil
		}
		relative, _ := filepath.Rel(directory, path)
		relative = filepath.ToSlash(relative)
		if relative == "infrastructure.lock" || relative == "ready" {
			return nil
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) || (info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0022 != 0) {
			return errors.New("operator_runtime_ownership_invalid")
		}
		if entry.IsDir() {
			if entry.Name() == "__pycache__" {
				return nil
			}
			contents[relative] = []any{"directory", uint32(info.Mode().Perm())}
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			valid := relative == "venv/lib64" && target == "lib"
			if strings.HasPrefix(relative, "venv/bin/python") {
				valid = target == "python3" || target == "python" || target == "/usr/bin/python3" || regexp.MustCompile(`^/usr/bin/python3\.(12|13|14)$`).MatchString(target)
			}
			if !valid {
				return errors.New("operator_runtime_symlink_invalid")
			}
			contents[relative] = []any{"link", target}
			return nil
		}
		if !info.Mode().IsRegular() || owner.Nlink != 1 {
			return errors.New("operator_runtime_member_invalid")
		}
		if filepath.Base(filepath.Dir(path)) == "__pycache__" {
			match := regexp.MustCompile(`^(.+)\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc$`).FindStringSubmatch(entry.Name())
			if len(match) == 2 {
				source := filepath.Join(filepath.Dir(filepath.Dir(path)), match[1]+".py")
				if info, err := os.Lstat(source); err == nil && info.Mode().IsRegular() {
					return nil
				}
			}
		}
		checksum, err := sourceSHA(path)
		if err != nil {
			return err
		}
		contents[relative] = []any{"file", checksum, uint32(info.Mode().Perm())}
		return nil
	})
	return contents, err
}

func sealPreparedOperatorRuntime(directory, sha string) error {
	path := filepath.Join(filepath.Dir(directory), "runtime-retention")
	if err := ensurePrivateBootstrapDirectory(path); err != nil {
		return err
	}
	contents, err := operatorRuntimeInventory(directory)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(map[string]any{"schema": 1, "path": directory, "dependency_sha256": sha, "inventory": contents})
	if err != nil {
		return err
	}
	return writeUpgradeInput(filepath.Join(path, filepath.Base(directory)+".json"), raw)
}

func pinOperatorRuntimeForOperation(directory, executable string) (func(), error) {
	release, err := pinOperatorRuntime(executable)
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(executable)))
	if regexp.MustCompile(`^runtime-[a-f0-9]{64}$`).MatchString(filepath.Base(root)) {
		raw, _ := json.Marshal(map[string]string{"runtime_directory": root})
		if err = writeUpgradeInput(filepath.Join(directory, "runtime-use.json"), raw); err != nil {
			release()
			return nil, err
		}
	}
	return release, nil
}

func sameOperatorInventory(left, right map[string]any) bool {
	a, err := json.Marshal(left)
	if err != nil {
		return false
	}
	b, err := json.Marshal(right)
	return err == nil && string(a) == string(b)
}

// collectCompletedOperatorArtifacts bounds the operator machine's private cache.
// Its caller holds the operator lease. Metadata is never removed. Runtime locks
// additionally serialize every preparer/user, including callers without that lease.
func collectCompletedOperatorArtifacts(root string, keep ...*automationRelease) error {
	if err := operatorPrivate(root, true); err != nil {
		return err
	}
	versions, dependencies := map[string]bool{}, map[string]bool{}
	for _, manifest := range keep {
		if manifest == nil {
			continue
		}
		versions[manifest.Version] = true
		for _, asset := range manifest.Assets {
			if strings.HasPrefix(asset.Name, "ultra-ansible-runtime-linux-") {
				dependencies[asset.SHA] = true
			}
		}
	}
	if len(versions) == 0 {
		return errors.New("operator_retention_active_identity_required")
	}
	operations := map[string]operatorCompletion{}
	refs := map[string]bool{}
	if entries, err := os.ReadDir(filepath.Join(root, "runtime-retention")); err == nil {
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), "runtime-use-") || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(root, "runtime-retention", entry.Name())
			if operatorPrivate(path, false) != nil {
				continue
			}
			raw, err := os.ReadFile(path)
			if err != nil || len(raw) > 4096 {
				continue
			}
			var ref map[string]string
			if json.Unmarshal(raw, &ref) != nil || !filepath.IsAbs(ref["stage_directory"]) || !filepath.IsAbs(ref["runtime_directory"]) {
				continue
			}
			if !operatorStageReferenceCompleted(ref["stage_directory"]) {
				refs[ref["runtime_directory"]] = true
			}
		}
	}

	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() && (entry.Name() == "bundle" || entry.Name() == "recovery-bundle" || entry.Name() == "ansible-tmp" || entry.Name() == "releases" || entry.Name() == "downloads" || strings.HasPrefix(entry.Name(), "runtime-")) {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			if _, err := os.Lstat(filepath.Join(path, operatorCompletionFile)); err == nil {
				if okay, err := completedOperatorOperation(path, "upgrade", ""); okay && err == nil {
					raw, _ := os.ReadFile(filepath.Join(path, operatorCompletionFile))
					var state operatorCompletion
					_ = json.Unmarshal(raw, &state)
					operations[path] = state
					return filepath.SkipDir
				}
				if okay, err := completedOperatorOperation(path, "bootstrap", ""); okay && err == nil {
					raw, _ := os.ReadFile(filepath.Join(path, operatorCompletionFile))
					var state operatorCompletion
					_ = json.Unmarshal(raw, &state)
					operations[path] = state
					return filepath.SkipDir
				}
			}
			return nil
		}
		if entry.Name() != "request.json" && entry.Name() != "runtime-use.json" {
			return nil
		}
		if err := operatorPrivate(path, false); err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil || len(raw) > 4<<20 {
			return errors.New("operator_retention_live_reference_invalid")
		}
		var value any
		if json.Unmarshal(raw, &value) != nil {
			return errors.New("operator_retention_live_reference_invalid")
		}
		collectOperatorReferences(value, refs)
		return nil
	})
	if err != nil {
		return err
	}
	protected := func(path string) bool {
		for ref := range refs {
			if ref == path || strings.HasPrefix(ref, path+string(os.PathSeparator)) || strings.HasPrefix(path, strings.TrimSuffix(ref, string(os.PathSeparator))+string(os.PathSeparator)) {
				return true
			}
		}
		return false
	}
	for directory, state := range operations {
		payloads := map[string]map[string]any{}
		for relative, contents := range state.Payloads {
			payloads[relative] = contents
		}
		for relative, receipt := range state.BundleReceipts {
			if filepath.IsAbs(relative) || strings.Contains(relative, "..") || filepath.Base(relative) != "bundle" || receipt != filepath.ToSlash(filepath.Join(filepath.Dir(relative), "bundle.retention.json")) {
				return errors.New("operator_retention_bundle_reference_invalid")
			}
			raw, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(receipt)))
			if err != nil {
				return err
			}
			var proof struct {
				Path      string         `json:"path"`
				Inventory map[string]any `json:"inventory"`
			}
			if json.Unmarshal(raw, &proof) != nil || proof.Path != filepath.Join(directory, filepath.FromSlash(relative)) {
				return errors.New("operator_retention_bundle_reference_invalid")
			}
			payloads[relative] = normalizeOperatorBundleInventory(proof.Inventory)
		}
		for relative, expected := range payloads {
			if filepath.IsAbs(relative) || strings.Contains(relative, "..") || (filepath.Base(relative) != "bundle" && filepath.Base(relative) != "recovery-bundle" && relative != "automation-sources/tools" && relative != "automation-sources/bootstrap_plan.py") {
				return errors.New("operator_retention_payload_path_invalid")
			}
			path := filepath.Join(directory, relative)
			if protected(path) {
				continue
			}
			if _, err := os.Lstat(path); os.IsNotExist(err) {
				continue
			}
			actual, err := operatorPayloadContents(path)
			if err != nil {
				continue
			}
			if !operatorDeletionPermitted(root, path, actual, expected) {
				continue
			}
			if err = os.RemoveAll(path); err != nil {
				return err
			}
			if err = syncUpgradeDirectory(filepath.Dir(path)); err != nil {
				return err
			}
		}
	}
	members, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range members {
		if !regexp.MustCompile(`^runtime-[a-f0-9]{64}$`).MatchString(entry.Name()) || dependencies[strings.TrimPrefix(entry.Name(), "runtime-")] {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if protected(path) {
			continue
		}
		release, err := operatorRuntimeLock(path, true)
		if err != nil {
			continue
		}
		err = func() error {
			defer release()
			proof := filepath.Join(root, "runtime-retention", entry.Name()+".json")
			if err := operatorPrivate(proof, false); err != nil {
				return nil
			}
			raw, err := os.ReadFile(proof)
			if err != nil || len(raw) > 4<<20 {
				return nil
			}
			var state struct {
				Schema     int            `json:"schema"`
				Path       string         `json:"path"`
				Dependency string         `json:"dependency_sha256"`
				Inventory  map[string]any `json:"inventory"`
			}
			if json.Unmarshal(raw, &state) != nil || state.Schema != 1 || state.Path != path || state.Dependency != strings.TrimPrefix(entry.Name(), "runtime-") {
				return nil
			}
			actual, err := operatorRuntimeInventory(path)
			if err != nil || !operatorDeletionPermitted(root, path, actual, state.Inventory) {
				return nil
			}
			if err = os.RemoveAll(path); err != nil {
				return err
			}
			if err = syncUpgradeDirectory(root); err != nil {
				return err
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func collectOperatorReferences(value any, refs map[string]bool) {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			selected := key == "runtime_directory" || key == "artifact_paths" || key == "controller_directory" || key == "release_dir" || key == "source" || key == "ultra_previous_controller_directory" || key == "ultra_controller_directory" || key == "ultra_release_probe_executable" || key == "ultra_restore_script_directory" || (strings.HasPrefix(key, "ultra_") && (strings.HasSuffix(key, "_source") || strings.HasSuffix(key, "_archive")))
			if selected {
				collectOperatorPathValues(child, refs)
			} else {
				collectOperatorReferences(child, refs)
			}
		}
	case []any:
		for _, child := range item {
			collectOperatorReferences(child, refs)
		}
	}
}
func collectOperatorPathValues(value any, refs map[string]bool) {
	switch item := value.(type) {
	case string:
		if filepath.IsAbs(item) {
			refs[filepath.Clean(item)] = true
		}
	case map[string]any:
		for _, child := range item {
			collectOperatorPathValues(child, refs)
		}
	case []any:
		for _, child := range item {
			collectOperatorPathValues(child, refs)
		}
	}
}

func operatorPayloadContents(path string) (map[string]any, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return operatorPayloadInventory(path)
	}
	if err := operatorPrivate(path, false); err != nil {
		return nil, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Nlink != 1 {
		return nil, errors.New("operator_retention_payload_invalid")
	}
	hash, err := sourceSHA(path)
	if err != nil {
		return nil, err
	}
	return map[string]any{"": []any{"file", hash, uint32(info.Mode().Perm())}}, nil
}

// Authenticate the accepted mutator generation, not merely an arbitrary set of
// terminal children. Failed superseded observations remain audit-only members.
func operatorWinningChain(directory, kind string, manifest *automationRelease, manifestSHA string) error {
	successful := func(stage, operation string, releaseIdentity bool) error {
		for _, name := range []string{"job.json", "request.json", "receipt.json"} {
			if err := operatorPrivate(filepath.Join(stage, name), false); err != nil {
				return err
			}
		}
		raw, err := os.ReadFile(filepath.Join(stage, "job.json"))
		if err != nil {
			return err
		}
		var job struct {
			Operation string `json:"operation"`
			Hash      string `json:"request_sha256"`
		}
		if json.Unmarshal(raw, &job) != nil || job.Operation != operation {
			return errors.New("operator_retention_winning_job_invalid")
		}
		raw, err = os.ReadFile(filepath.Join(stage, "receipt.json"))
		if err != nil {
			return err
		}
		var receipt struct {
			State string `json:"state"`
			Hash  string `json:"request_sha256"`
		}
		if json.Unmarshal(raw, &receipt) != nil || receipt.State != "succeeded" || receipt.Hash != job.Hash {
			return errors.New("operator_retention_winning_receipt_invalid")
		}
		requestPath := filepath.Join(stage, "request.json")
		hash, err := sourceSHA(requestPath)
		if err != nil || hash != job.Hash {
			return errors.New("operator_retention_winning_request_changed")
		}
		if releaseIdentity {
			raw, err = os.ReadFile(requestPath)
			if err != nil {
				return err
			}
			var request struct {
				Variables map[string]any `json:"variables"`
			}
			if json.Unmarshal(raw, &request) != nil || request.Variables["ultra_release_version"] != manifest.Version || request.Variables["ultra_release_manifest_sha256"] != manifestSHA {
				return errors.New("operator_retention_winning_release_changed")
			}
			projected, _ := json.Marshal(request.Variables["ultra_release_manifest"])
			var release automationRelease
			if json.Unmarshal(projected, &release) != nil || release.Version != manifest.Version || release.SourceCommit != manifest.SourceCommit {
				return errors.New("operator_retention_winning_release_changed")
			}
		}
		return nil
	}
	switch kind {
	case "upgrade":
		generation, err := upgradeActivationGeneration(directory, false)
		if err != nil {
			return err
		}
		if err = successful(filepath.Join(directory, "activate"), "upgrade", true); err != nil {
			return err
		}
		for _, step := range []string{"publish", "commit"} {
			operation := "publish-release"
			if step == "commit" {
				operation = "commit-release"
			}
			if err = successful(upgradeDependentStageDirectory(directory, step, generation), operation, true); err != nil {
				return err
			}
		}
	case "bootstrap":
		path := filepath.Join(directory, "finalization.json")
		if err := operatorPrivate(path, false); err != nil {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var state bootstrapFinalization
		if json.Unmarshal(raw, &state) != nil || state.Schema != 1 || state.ID != lifecycleID(directory) || state.Phase != "released" {
			return errors.New("operator_retention_bootstrap_not_released")
		}
		_, hash, err := bootstrapFinalizationInputs(directory)
		if err != nil || hash != state.InventorySHA {
			return errors.New("operator_retention_bootstrap_inventory_changed")
		}
		frozen, _, err := bootstrapFinalizationInputs(directory)
		if err != nil {
			return err
		}
		generation, err := bootstrapMutationGeneration(directory, frozen)
		if err != nil {
			return err
		}
		if err = successful(bootstrapMutationStage(directory, "automation", generation), "bootstrap-automation", false); err != nil {
			return err
		}
		raw, err = os.ReadFile(filepath.Join(bootstrapMutationStage(directory, "automation", generation), "request.json"))
		if err != nil {
			return err
		}
		var request struct {
			Variables map[string]any `json:"variables"`
		}
		if json.Unmarshal(raw, &request) != nil {
			return errors.New("operator_retention_bootstrap_release_invalid")
		}
		config, _ := request.Variables["ultra_automation_configuration"].(map[string]any)
		if config["version"] != manifest.Version {
			return errors.New("operator_retention_bootstrap_release_changed")
		}
	default:
		return errors.New("operator_retention_kind_invalid")
	}
	return nil
}

// Recursive deletion can be interrupted inside a tree. Only a durable intent
// written after full identity validation permits a later unchanged subset.
func operatorDeletionPermitted(root, path string, actual, expected map[string]any) bool {
	receipts := filepath.Join(root, "runtime-retention")
	if ensurePrivateBootstrapDirectory(receipts) != nil {
		return false
	}
	sum := sha256.Sum256([]byte(path))
	intent := filepath.Join(receipts, "operator-delete-"+hex.EncodeToString(sum[:])+".json")
	raw, _ := json.Marshal(map[string]any{"schema": 1, "path": path, "inventory": expected})
	if _, err := os.Lstat(intent); os.IsNotExist(err) {
		if !sameOperatorInventory(actual, expected) {
			return false
		}
		return writeUpgradeInput(intent, raw) == nil
	}
	if operatorPrivate(intent, false) != nil {
		return false
	}
	prior, err := os.ReadFile(intent)
	if err != nil || string(prior) != string(raw) {
		return false
	}
	for key, value := range actual {
		if filepath.Base(filepath.Dir(key)) == "__pycache__" {
			match := regexp.MustCompile(`^(.+)\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc$`).FindStringSubmatch(filepath.Base(key))
			if len(match) == 2 {
				source := filepath.ToSlash(filepath.Join(filepath.Dir(filepath.Dir(key)), match[1]+".py"))
				if entry, ok := expected[source].([]any); ok && len(entry) > 0 && entry[0] == "file" {
					continue
				}
			}
		}
		wanted, ok := expected[key]
		if !ok {
			return false
		}
		a, _ := json.Marshal(value)
		b, _ := json.Marshal(wanted)
		if string(a) != string(b) {
			return false
		}
	}
	return true
}

func normalizeOperatorBundleInventory(contents map[string]any) map[string]any {
	result := map[string]any{}
	for key, value := range contents {
		if filepath.Base(key) == "__pycache__" {
			continue
		}
		if filepath.Base(filepath.Dir(key)) == "__pycache__" {
			match := regexp.MustCompile(`^(.+)\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc$`).FindStringSubmatch(filepath.Base(key))
			if len(match) == 2 {
				source := filepath.ToSlash(filepath.Join(filepath.Dir(filepath.Dir(key)), match[1]+".py"))
				if entry, ok := contents[source].([]any); ok && len(entry) > 0 && entry[0] == "file" {
					continue
				}
			}
		}
		result[key] = value
	}
	return result
}

func proveBootstrapEmergencySources(directory string, manifest *automationRelease, manifestSHA string) error {
	frozen, _, err := bootstrapFinalizationInputs(directory)
	if err != nil {
		return err
	}
	generation, err := bootstrapMutationGeneration(directory, frozen)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(filepath.Join(bootstrapMutationStage(directory, "automation", generation), "request.json"))
	if err != nil {
		return err
	}
	var request struct {
		Variables map[string]any `json:"variables"`
	}
	if json.Unmarshal(raw, &request) != nil {
		return errors.New("operator_retention_bootstrap_emergency_invalid")
	}
	manifestPath, ok := request.Variables["ultra_automation_manifest_source"].(string)
	if !ok {
		return errors.New("operator_retention_bootstrap_emergency_invalid")
	}
	hash, err := sourceSHA(manifestPath)
	if err != nil || hash != manifestSHA {
		return errors.New("operator_retention_bootstrap_manifest_changed")
	}
	emergency, ok := request.Variables["ultra_automation_emergency_source"].(string)
	if !ok {
		return errors.New("operator_retention_bootstrap_emergency_invalid")
	}
	asset, err := upgradeAsset(manifest, filepath.Base(emergency))
	if err != nil || !strings.HasPrefix(asset.Name, "ultra-relay-linux-") {
		return errors.New("operator_retention_bootstrap_emergency_invalid")
	}
	hash, err = sourceSHA(emergency)
	if err != nil || hash != asset.SHA {
		return errors.New("operator_retention_bootstrap_emergency_changed")
	}
	return nil
}

// Explicit stage commands keep their reference beside the dependency receipt,
// outside frozen operation metadata, until the owning transaction is complete.
func pinExplicitOperatorRuntime(stage, executable string) (func(), error) {
	release, err := pinOperatorRuntime(executable)
	if err != nil {
		return nil, err
	}
	runtimeRoot := filepath.Dir(filepath.Dir(filepath.Dir(executable)))
	if !regexp.MustCompile(`^runtime-[a-f0-9]{64}$`).MatchString(filepath.Base(runtimeRoot)) {
		return release, nil
	}
	absolute, err := filepath.Abs(stage)
	if err != nil {
		release()
		return nil, err
	}
	raw, _ := json.Marshal(map[string]string{"stage_directory": absolute, "runtime_directory": runtimeRoot})
	sum := sha256.Sum256([]byte(absolute))
	reference := filepath.Join(filepath.Dir(runtimeRoot), "runtime-retention", "runtime-use-"+hex.EncodeToString(sum[:])+".json")
	if err = writeUpgradeInput(reference, raw); err != nil {
		release()
		return nil, err
	}
	return release, nil
}
func operatorStageReferenceCompleted(stage string) bool {
	for directory := filepath.Dir(stage); filepath.Dir(directory) != directory; directory = filepath.Dir(directory) {
		if _, err := os.Lstat(filepath.Join(directory, operatorCompletionFile)); err == nil {
			for _, kind := range []string{"bootstrap", "upgrade"} {
				if cached, err := completedOperatorOperation(directory, kind, ""); cached && err == nil {
					return true
				}
			}
			return false
		}
	}
	// Standalone collector success has an explicit cache contract and no outer
	// resume/rollback lifecycle. Other fixed stages remain conservatively pinned.
	path := filepath.Join(stage, "job.json")
	if operatorPrivate(path, false) != nil {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var job struct {
		Operation string `json:"operation"`
		Hash      string `json:"request_sha256"`
	}
	if json.Unmarshal(raw, &job) != nil || job.Operation != "retain-artifacts" {
		return false
	}
	path = filepath.Join(stage, "receipt.json")
	if operatorPrivate(path, false) != nil {
		return false
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		return false
	}
	var receipt struct {
		State string `json:"state"`
		Hash  string `json:"request_sha256"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.State != "succeeded" || receipt.Hash != job.Hash {
		return false
	}
	hash, err := sourceSHA(filepath.Join(stage, "request.json"))
	return err == nil && hash == job.Hash
}

// A removed source permits historical replay. A present source must still be
// exactly the completed target; replacing a same-named release is never cached.
func matchCompletedOperatorRelease(directory, releaseDir string) error {
	path := filepath.Join(releaseDir, "release-manifest.json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("operator_retention_completed_release_changed")
	}
	raw, err := os.ReadFile(filepath.Join(directory, operatorCompletionFile))
	if err != nil {
		return err
	}
	var state operatorCompletion
	if json.Unmarshal(raw, &state) != nil {
		return errors.New("operator_retention_completion_invalid")
	}
	hash, err := sourceSHA(path)
	if err != nil || hash != state.ManifestSHA {
		return errors.New("operator_retention_completed_release_changed")
	}
	return nil
}
