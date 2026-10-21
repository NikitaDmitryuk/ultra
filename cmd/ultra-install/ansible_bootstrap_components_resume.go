package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

const bootstrapComponentCompletionFile = "linked-bootstrap-completed.json"

type bootstrapComponentCompletion struct {
	Schema     int               `json:"schema"`
	Source     string            `json:"source"`
	LinkedRoot string            `json:"linked_root"`
	Baseline   map[string]string `json:"baseline"`
	Evidence   map[string]string `json:"evidence"`
}

// Only an outstanding first-generation legacy bootstrap can receive a linked
// continuation. Even a pending rollback invalidates every previous completion.
func validateBootstrapComponentContinuation(stage string) (map[string]any, map[string]any, map[string]string, error) {
	fail := func(err error) (map[string]any, map[string]any, map[string]string, error) { return nil, nil, nil, err }
	if !filepath.IsAbs(stage) || filepath.Clean(stage) != stage || filepath.Base(stage) != "apply" {
		return fail(errors.New("bootstrap_component_original_stage_invalid"))
	}
	entries, err := os.ReadDir(filepath.Dir(stage))
	if err != nil {
		return fail(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "rollback-adoption") || strings.HasPrefix(entry.Name(), "rollback-generation-") {
			return fail(errors.New("bootstrap_component_original_rollback_present"))
		}
	}
	baseline := map[string]string{}
	input := map[string][]byte{}
	for _, name := range []string{"request.json", "job.json", "receipt.json"} {
		raw, err := readBootstrapGenerationInput(filepath.Join(stage, name))
		if err != nil {
			return fail(err)
		}
		input[name] = raw
		baseline[name] = bootstrapComponentDigest(raw)
	}
	var request struct {
		Inventory map[string]any `json:"inventory"`
		Variables map[string]any `json:"variables"`
	}
	var job, receipt map[string]any
	if json.Unmarshal(input["request.json"], &request) != nil || json.Unmarshal(input["job.json"], &job) != nil ||
		json.Unmarshal(input["receipt.json"], &receipt) != nil ||
		request.Inventory == nil ||
		request.Variables == nil ||
		job["operation"] != "bootstrap" ||
		job["schema_version"] != float64(1) ||
		job["request_sha256"] != baseline["request.json"] ||
		job["binary_sha256"] != baseline["request.json"] ||
		receipt["operation"] != "bootstrap" ||
		receipt["schema_version"] != job["schema_version"] ||
		receipt["attempt"] != job["attempt"] ||
		receipt["request_sha256"] != job["request_sha256"] ||
		receipt["binary_sha256"] != job["binary_sha256"] ||
		(receipt["state"] != "failed" && receipt["state"] != "running") {
		return fail(errors.New("bootstrap_component_original_receipt_invalid"))
	}
	frozenRaw, err := readBootstrapGenerationInput(filepath.Join(filepath.Dir(stage), "inventory.frozen.json"))
	if err != nil {
		return fail(err)
	}
	var frozen map[string]any
	expected, _ := json.Marshal(request.Inventory)
	if json.Unmarshal(frozenRaw, &frozen) != nil {
		return fail(errors.New("bootstrap_component_frozen_inventory_invalid"))
	}
	actual, _ := json.Marshal(frozen)
	if !bytes.Equal(expected, actual) {
		return fail(errors.New("bootstrap_component_frozen_inventory_changed"))
	}
	baseline["inventory.frozen.json"] = bootstrapComponentDigest(frozenRaw)
	return request.Inventory, request.Variables, baseline, nil
}

func assertBootstrapComponentContinuationLifecycle(
	ctx context.Context,
	stage string,
	inventory, variables map[string]any,
	python, executable string,
) error {
	lock, ok := variables["ultra_lock_directory"].(string)
	if !ok || !filepath.IsAbs(lock) {
		return errors.New("bootstrap_component_original_lease_invalid")
	}
	if lock == bootstrapBrokerLockDirectory {
		return (deployansible.Client{Socket: bootstrapBrokerSocket}).ResumeLifecycleWithOperationLock(ctx, lifecycleID(filepath.Dir(stage)))
	}
	target, err := os.MkdirTemp(filepath.Dir(stage), "linked-lifecycle-resume-")
	if err != nil {
		return err
	}
	if err = os.Remove(target); err != nil {
		return err
	}
	receipt, err := deployansible.RunLocal(
		ctx,
		"lifecycle",
		inventory,
		map[string]any{
			"ultra_lock_directory":   lock,
			"ultra_lifecycle_id":     lifecycleID(filepath.Dir(stage)),
			"ultra_lifecycle_phase":  "applying",
			"ultra_lifecycle_resume": true,
			"ultra_lifecycle_drain":  false,
		},
		target,
		python,
		executable,
	)
	if err != nil {
		return err
	}
	if receipt.Result.Values["verified"] != true {
		return errors.New("bootstrap_component_lifecycle_unverified")
	}
	return nil
}

func publishBootstrapComponentContinuation(
	stage, linkedRoot string,
	inventory, variables map[string]any,
	baseline map[string]string,
) error {
	proof, err := bootstrapComponentContinuationProof(stage, linkedRoot, inventory, variables, baseline)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	if err = writeUpgradeInput(filepath.Join(filepath.Dir(stage), bootstrapComponentCompletionFile), raw); err != nil {
		return err
	}
	return syncUpgradeDirectory(filepath.Dir(stage))
}

// The operator's existing lease is held by the parent transaction. This consumer
// performs no transitions and never rewrites the original failure receipt.
func completedBootstrapComponentContinuation(stage string, inventory, variables map[string]any) (bool, error) {
	raw, err := readBootstrapGenerationInput(filepath.Join(filepath.Dir(stage), bootstrapComponentCompletionFile))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var saved bootstrapComponentCompletion
	if json.Unmarshal(raw, &saved) != nil || saved.Schema != 1 || saved.Source != stage {
		return false, errors.New("bootstrap_component_completion_invalid")
	}
	expected, err := bootstrapComponentContinuationProof(stage, saved.LinkedRoot, inventory, variables, saved.Baseline)
	if err != nil {
		return false, err
	}
	actual, _ := json.Marshal(expected)
	if !bytes.Equal(raw, actual) {
		return false, errors.New("bootstrap_component_completion_changed")
	}
	return true, nil
}

func bootstrapComponentContinuationProof(
	stage, linkedRoot string,
	inventory, variables map[string]any,
	baseline map[string]string,
) (bootstrapComponentCompletion, error) {
	fail := func(err error) (bootstrapComponentCompletion, error) { return bootstrapComponentCompletion{}, err }
	frozen, originalVars, current, err := validateBootstrapComponentContinuation(stage)
	if err != nil {
		return fail(err)
	}
	for _, pair := range [][2]any{{frozen, inventory}, {originalVars, variables}, {current, baseline}} {
		a, _ := json.Marshal(pair[0])
		b, _ := json.Marshal(pair[1])
		if !bytes.Equal(a, b) {
			return fail(errors.New("bootstrap_component_original_baseline_changed"))
		}
	}
	if !filepath.IsAbs(linkedRoot) || filepath.Clean(linkedRoot) != linkedRoot || filepath.Dir(linkedRoot) != filepath.Dir(stage) ||
		!regexp.MustCompile(`^linked-components-[a-f0-9]{16}$`).MatchString(filepath.Base(linkedRoot)) {
		return fail(errors.New("bootstrap_component_linked_root_invalid"))
	}
	anchor := filepath.Join(linkedRoot, "bootstrap-postgres")
	if err = deployansible.VerifyAdaptedBootstrapPostgres(inventory, variables, anchor, stage); err != nil {
		return fail(err)
	}
	anchorTree, err := bootstrapComponentBundleTree(filepath.Join(anchor, "bundle"))
	if err != nil {
		return fail(err)
	}
	anchorRaw, _ := json.Marshal(anchorTree)
	anchorHash := bootstrapComponentDigest(anchorRaw)
	anchorRequest, err := readBootstrapGenerationInput(filepath.Join(anchor, "request.json"))
	if err != nil {
		return fail(err)
	}
	evidence := map[string]string{}
	adapter, err := readBootstrapGenerationInput(filepath.Join(anchor, "bundle.adapter.json"))
	if err != nil {
		return fail(err)
	}
	evidence["adapter"] = bootstrapComponentDigest(adapter)
	aliases, err := bootstrapComponentExits(inventory)
	if err != nil {
		return fail(err)
	}
	pins := map[string]string{}
	verify := func(operation, name string, extra map[string]any) error {
		vars := map[string]any{}
		for k, v := range variables {
			vars[k] = v
		}
		for k, v := range extra {
			vars[k] = v
		}
		dir := filepath.Join(linkedRoot, name)
		if err := verifyBootstrapComponentReceipt(dir, operation, inventory, vars); err != nil {
			return err
		}
		tree, err := bootstrapComponentBundleTree(filepath.Join(dir, "bundle"))
		if err != nil {
			return err
		}
		treeRaw, _ := json.Marshal(tree)
		if !bytes.Equal(anchorRaw, treeRaw) {
			return errors.New("bootstrap_component_bundle_changed")
		}
		receipt, err := readBootstrapGenerationInput(filepath.Join(dir, "receipt.json"))
		if err != nil {
			return err
		}
		evidence[name+"/receipt"] = bootstrapComponentDigest(receipt)
		evidence[name+"/bundle"] = bootstrapComponentDigest(treeRaw)
		if dir != anchor {
			sourceRaw, err := readBootstrapGenerationInput(filepath.Join(dir, "bundle.source.json"))
			if err != nil {
				return err
			}
			var source map[string]any
			if json.Unmarshal(sourceRaw, &source) != nil || source["schema"] != float64(1) || source["source"] != anchor ||
				source["operation"] != operation ||
				source["source_request_sha256"] != bootstrapComponentDigest(anchorRequest) ||
				source["bundle_sha256"] != anchorHash {
				return errors.New("bootstrap_component_bundle_source_invalid")
			}
			evidence[name+"/source"] = bootstrapComponentDigest(sourceRaw)
		}
		if operation == "bootstrap-exit" {
			var value struct {
				Result struct {
					CertPin string `json:"cert_pin"`
				} `json:"result"`
			}
			_ = json.Unmarshal(receipt, &value)
			alias := stringValue(extra["ultra_bootstrap_exit_host"])
			name, err := bootstrapComponentCAName(inventory, alias)
			if err != nil {
				return err
			}
			if name == "" {
				pins[alias] = value.Result.CertPin
			}
		}
		return nil
	}
	if err = verify("bootstrap-postgres", "bootstrap-postgres", nil); err != nil {
		return fail(err)
	}
	for _, alias := range aliases {
		if err = verify("bootstrap-exit", "bootstrap-"+alias, map[string]any{"ultra_bootstrap_exit_host": alias}); err != nil {
			return fail(err)
		}
	}
	if err = verify("bootstrap-bridge", "bootstrap-bridge", map[string]any{"ultra_bootstrap_pins": pins}); err != nil {
		return fail(err)
	}
	return bootstrapComponentCompletion{Schema: 1, Source: stage, LinkedRoot: linkedRoot, Baseline: baseline, Evidence: evidence}, nil
}

func bootstrapComponentDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Mirrors the pinned tree's content/mode inventory, using private no-symlink
// reads so a completion cannot authenticate only a matching controller file.
func bootstrapComponentBundleTree(root string) (map[string]any, error) {
	tree := map[string]any{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("bootstrap_component_bundle_private_required")
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if rel != "." {
				tree[filepath.ToSlash(rel)] = []any{"directory", uint32(info.Mode().Perm())}
			}
			return nil
		}
		raw, err := readBootstrapGenerationInput(path)
		if err != nil {
			return err
		}
		tree[filepath.ToSlash(rel)] = []any{"file", bootstrapComponentDigest(raw), uint32(info.Mode().Perm())}
		return nil
	})
	return tree, err
}
