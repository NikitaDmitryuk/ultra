package main

import (
	"encoding/hex"
	"errors"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/google/uuid"
)

func validEnforcementSHA(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32 && strings.ToLower(value) == value
}

func validateEnforcementProof(proof, spec map[string]any) error {
	fail := errors.New("upgrade_controller_enforcement_proof_unverified")
	if len(proof) != 9 || proof["schema"] != float64(1) || proof["operation_id"] != spec["operation_id"] ||
		proof["scope_sha256"] != spec["scope_sha256"] || proof["manifest_sha256"] != spec["manifest_sha256"] {
		return fail
	}
	for _, key := range []string{"ledger_sha256", "machine_sha256"} {
		value, ok := proof[key].(string)
		if !ok || !validEnforcementSHA(value) {
			return fail
		}
	}
	candidate, ok := proof["candidate"].(map[string]any)
	if !ok {
		return fail
	}
	architecture, _ := candidate["architecture"].(string)
	candidates, _ := spec["candidates"].(map[string]any)
	entry, _ := candidates[architecture].(map[string]any)
	if entry == nil || !reflect.DeepEqual(candidate, entry["identity"]) {
		return fail
	}
	rollback, ok := proof["rollback"].(map[string]any)
	if !ok || len(rollback) != 6 {
		return fail
	}
	for _, key := range []string{"installer_sha256", "runtime_sha256", "unit_sha256", "tree_sha256"} {
		value, ok := rollback[key].(string)
		if !ok || !validEnforcementSHA(value) {
			return fail
		}
	}
	unit, unitOK := rollback["unit"].(string)
	directory, directoryOK := rollback["directory"].(string)
	if !unitOK || !directoryOK || len(unit) > 65536 || digestSHA256([]byte(unit)) != rollback["unit_sha256"] ||
		!strings.HasPrefix(directory, "/opt/ultra-ansible/releases/") || filepath.Clean(directory) != directory ||
		filepath.Dir(directory) != "/opt/ultra-ansible/releases" {
		return fail
	}
	lifecycle, ok := proof["source_lifecycle"].(map[string]any)
	if !ok || len(lifecycle) != 2 || lifecycle["phase"] != "released" {
		return fail
	}
	id, ok := lifecycle["id"].(string)
	parsed, err := uuid.Parse(id)
	if !ok || err != nil || parsed.String() != id {
		return fail
	}
	return nil
}
