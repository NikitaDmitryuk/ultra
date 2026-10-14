package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

var bootstrapComponentAlias = regexp.MustCompile(`^exit_(0|[1-9][0-9]*)$`)
var bootstrapComponentPin = regexp.MustCompile(`^[a-f0-9]{64}$`)

// The full frozen inventory remains the identity boundary for every stage. Only
// the fixed playbook's target and verified receipt pins vary between components.
func runBootstrapComponents(ctx context.Context, inventory, variables map[string]any, directory string, generation int, python, executable string) error {
	return runBootstrapComponentsAdapted(ctx, inventory, variables, directory, generation, "", python, executable)
}

func runBootstrapComponentsAdapted(ctx context.Context, inventory, variables map[string]any, directory string, generation int, sourceStage, python, executable string) error {
	aliases, err := bootstrapComponentExits(inventory)
	if err != nil {
		return err
	}
	anchor := bootstrapMutationStage(directory, "bootstrap-postgres", generation)
	original := bootstrapMutationStage(directory, "bootstrap-postgres", 1)
	run := func(operation, stage string, extra map[string]any) (deployansible.Receipt, error) {
		vars := make(map[string]any, len(variables)+len(extra))
		for key, value := range variables {
			vars[key] = value
		}
		for key, value := range extra {
			vars[key] = value
		}
		target := bootstrapMutationStage(directory, stage, generation)
		source := anchor
		if generation > 1 && operation == "bootstrap-postgres" {
			source = original
		}
		var receipt deployansible.Receipt
		var runErr error
		if generation == 1 && operation == "bootstrap-postgres" && sourceStage != "" {
			receipt, runErr = deployansible.RunLocalRetryFailedAdaptedBootstrapPostgres(ctx, inventory, vars, target, sourceStage, python, executable)
		} else if target == source {
			receipt, runErr = deployansible.RunLocalRetryFailed(ctx, operation, inventory, vars, target, python, executable)
		} else {
			receipt, runErr = deployansible.RunLocalRetryFailedPinned(ctx, operation, inventory, vars, target, source, python, executable)
		}
		if runErr != nil {
			return receipt, runErr
		}
		if err := verifyBootstrapComponentReceipt(target, operation, inventory, vars); err != nil {
			return receipt, err
		}
		return receipt, nil
	}
	if _, err = run("bootstrap-postgres", "bootstrap-postgres", nil); err != nil {
		return err
	}
	pins := make(map[string]string, len(aliases))
	for _, alias := range aliases {
		receipt, runErr := run("bootstrap-exit", "bootstrap-"+alias, map[string]any{"ultra_bootstrap_exit_host": alias})
		if runErr != nil {
			return runErr
		}
		if receipt.Result.Values["exit_host"] != alias || !bootstrapComponentPin.MatchString(receipt.Result.CertPin) {
			return errors.New("bootstrap_component_exit_receipt_invalid")
		}
		pins[alias] = receipt.Result.CertPin
	}
	_, err = run("bootstrap-bridge", "bootstrap-bridge", map[string]any{"ultra_bootstrap_pins": pins})
	return err
}

func bootstrapComponentExits(inventory map[string]any) ([]string, error) {
	all, _ := inventory["all"].(map[string]any)
	children, _ := all["children"].(map[string]any)
	exits, _ := children["exits"].(map[string]any)
	hosts, _ := exits["hosts"].(map[string]any)
	aliases := make([]string, 0, len(hosts))
	for alias := range hosts {
		if !bootstrapComponentAlias.MatchString(alias) {
			return nil, errors.New("bootstrap_component_exit_alias_invalid")
		}
		aliases = append(aliases, alias)
	}
	sort.Slice(aliases, func(i, j int) bool {
		a, _ := strconv.Atoi(aliases[i][5:])
		b, _ := strconv.Atoi(aliases[j][5:])
		return a < b
	})
	return aliases, nil
}

// Successful cache entries are usable only if they prove this exact operation,
// request, and attempt. A plausible result alone must never skip a component.
func verifyBootstrapComponentReceipt(directory, operation string, inventory, variables map[string]any) error {
	request, err := readBootstrapGenerationInput(filepath.Join(directory, "request.json"))
	if err != nil {
		return err
	}
	expected, err := json.Marshal(map[string]any{"inventory": inventory, "variables": variables})
	if err != nil {
		return err
	}
	jobRaw, err := readBootstrapGenerationInput(filepath.Join(directory, "job.json"))
	if err != nil {
		return err
	}
	receiptRaw, err := readBootstrapGenerationInput(filepath.Join(directory, "receipt.json"))
	if err != nil {
		return err
	}
	var job, receipt map[string]any
	hash := sha256.Sum256(request)
	digest := hex.EncodeToString(hash[:])
	if !bytes.Equal(expected, request) || json.Unmarshal(jobRaw, &job) != nil || json.Unmarshal(receiptRaw, &receipt) != nil || job["operation"] != operation || receipt["operation"] != operation || job["schema_version"] != float64(1) || receipt["schema_version"] != job["schema_version"] || job["request_sha256"] != digest || job["binary_sha256"] != digest || receipt["request_sha256"] != digest || receipt["binary_sha256"] != digest || receipt["attempt"] != job["attempt"] || receipt["state"] != "succeeded" {
		return errors.New("bootstrap_component_receipt_invalid")
	}
	result, _ := receipt["result"].(map[string]any)
	if result["verified"] != true {
		return errors.New("bootstrap_component_unverified")
	}
	if operation == "bootstrap-exit" && (result["exit_host"] != variables["ultra_bootstrap_exit_host"] || !bootstrapComponentPin.MatchString(stringValue(result["cert_pin"]))) {
		return errors.New("bootstrap_component_exit_receipt_invalid")
	}
	return nil
}

func stringValue(value any) string { text, _ := value.(string); return text }
