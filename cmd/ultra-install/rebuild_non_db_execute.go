package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

const retainedPrimaryRebuildOperation = "rebuild-retained-primary"
const retainedBridgeRebuildOperation = "rebuild-retained-bridge"

type retainedPrimaryIdentity struct {
	RouteSHA256       string `json:"route_sha256,omitempty"`
	SystemIdentifier  string `json:"system_identifier"`
	Database          string `json:"database"`
	DatabaseOID       uint32 `json:"database_oid"`
	MigrationsSHA256  string `json:"migrations_sha256"`
	MigrationVersions string `json:"migration_versions"`
}

type retainedPrimaryRebuildInput struct {
	BridgeOnly                 bool                `json:",omitempty"`
	RetainedExit               *retainedBridgeExit `json:",omitempty"`
	Inventory                  map[string]any
	Variables                  map[string]any
	JournalSHA256              string
	ConfigSHA256               string
	ManifestSHA256             string
	CandidateMigrationsSHA256  string
	CandidateMigrationVersions string
	FenceEvidenceSHA256        string
	Primary                    retainedPrimaryIdentity
	Directory                  string
	Python                     string
	Executable                 string
}

type retainedPrimaryRebuildDependencies struct {
	// VerifyFence must independently verify a durable admission fence and all
	// former execution capabilities. A current process census alone is insufficient.
	// The caller retains that fence for the entire execution and receipt publication.
	VerifyFence    func(context.Context, retainedPrimaryRebuildInput) error
	ObservePrimary func(context.Context, retainedPrimaryRebuildInput) (retainedPrimaryIdentity, error)
	Run            func(context.Context, string, map[string]any, map[string]any, string, string, string) (deployansible.Receipt, error)
}

type retainedPrimaryRebuildReceipt struct {
	Protocol                     string                  `json:"protocol"`
	BindingSHA256                string                  `json:"binding_sha256"`
	OriginalJournalSHA256        string                  `json:"original_journal_sha256"`
	ConfigSHA256                 string                  `json:"config_sha256"`
	ManifestSHA256               string                  `json:"manifest_sha256"`
	Primary                      retainedPrimaryIdentity `json:"primary"`
	FenceEvidenceSHA256          string                  `json:"fence_evidence_sha256"`
	OriginalJournalArchiveSHA256 string                  `json:"original_journal_archive_sha256"`
	CandidateMigrationsSHA256    string                  `json:"candidate_migrations_sha256"`
	RequestSHA256                string                  `json:"request_sha256"`
	BinarySHA256                 string                  `json:"binary_sha256"`
	Verified                     bool                    `json:"verified"`
}

// runRetainedPrimaryRebuild never retires the original journal or claims that a
// caller-supplied envelope proves fencing. Without real verifier dependencies it
// cannot execute. The only runner operation is the embedded retained-primary playbook.
func runRetainedPrimaryRebuild(ctx context.Context, in retainedPrimaryRebuildInput, deps retainedPrimaryRebuildDependencies) error {
	if err := validateRetainedPrimaryRebuild(in); err != nil {
		return err
	}
	if deps.VerifyFence == nil || deps.ObservePrimary == nil {
		return errors.New("retained_primary_verifier_required")
	}
	if deps.Run == nil {
		deps.Run = deployansible.RunLocal
	}
	// Clone inputs before invoking dependencies so their caller cannot change the
	// frozen maps between the verified binding and RunLocal's frozen request.
	raw, err := json.Marshal(in)
	if err != nil {
		return errors.New("retained_primary_inputs_invalid")
	}
	var frozen retainedPrimaryRebuildInput
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&frozen); err != nil {
		return errors.New("retained_primary_inputs_invalid")
	}
	in = frozen
	// Bind the normalized representation used by the runner. Typed nested structs
	// become maps during freezing; their original field order is not canonical.
	raw, err = json.Marshal(in)
	if err != nil {
		return errors.New("retained_primary_inputs_invalid")
	}
	if err = validateRetainedPrimaryRebuild(in); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	binding := digestSHA256(raw)
	if err = deps.VerifyFence(ctx, in); err != nil {
		return errors.New("retained_primary_fence_unverified")
	}
	identity, err := deps.ObservePrimary(ctx, in)
	if err != nil || identity != in.Primary {
		return errors.New("retained_primary_identity_changed")
	}
	vars := make(map[string]any, len(in.Variables))
	for key, value := range in.Variables {
		vars[key] = value
	}
	vars["ultra_retained_primary"] = map[string]any{
		"system_identifier": in.Primary.SystemIdentifier,
		"database":          in.Primary.Database,
		"database_oid":      in.Primary.DatabaseOID,
		"migrations_sha256": in.Primary.MigrationsSHA256,
	}
	vars["ultra_retained_candidate_migration_versions"] = in.CandidateMigrationVersions
	vars["ultra_retained_recovery_binding_sha256"] = binding
	vars["ultra_bootstrap_exit_host"] = "exit_0"
	vars["ultra_preserve_runtime"] = false
	if err = ctx.Err(); err != nil {
		return err
	}
	result, err := deps.Run(
		ctx,
		retainedRebuildOperation(in),
		in.Inventory,
		vars,
		filepath.Join(in.Directory, "execute"),
		in.Python,
		in.Executable,
	)
	if err != nil {
		return fmt.Errorf(
			"retained_primary_execution_failed: stage=%q node=%q code=%q",
			result.Diagnostic.Stage,
			result.Diagnostic.Node,
			result.Diagnostic.Code,
		)
	}
	if result.State != "succeeded" || !rebuildSHA.MatchString(result.RequestSHA256) || !rebuildSHA.MatchString(result.BinarySHA256) {
		return errors.New("retained_primary_execution_unverified")
	}
	for _, key := range []string{"verified", "retained_primary_verified", "relay_ready", "bot_ready", "main_exit_ready"} {
		if result.Result.Values[key] != true {
			return errors.New("retained_primary_health_unverified")
		}
	}
	if result.Result.Values["recovery_binding_sha256"] != binding {
		return errors.New("retained_primary_result_binding_invalid")
	}
	if err = deps.VerifyFence(ctx, in); err != nil {
		return errors.New("retained_primary_fence_unverified")
	}
	identity, err = deps.ObservePrimary(ctx, in)
	if err != nil || identity != in.Primary {
		return errors.New("retained_primary_identity_changed")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	finalInput, err := json.Marshal(in)
	if err != nil || digestSHA256(finalInput) != binding {
		return errors.New("retained_primary_inputs_changed")
	}
	receipt := retainedPrimaryRebuildReceipt{
		Protocol:                     "ultra-retained-primary-rebuild-v1",
		BindingSHA256:                binding,
		OriginalJournalSHA256:        in.JournalSHA256,
		ConfigSHA256:                 in.ConfigSHA256,
		ManifestSHA256:               in.ManifestSHA256,
		Primary:                      in.Primary,
		FenceEvidenceSHA256:          in.FenceEvidenceSHA256,
		OriginalJournalArchiveSHA256: in.JournalSHA256,
		CandidateMigrationsSHA256:    in.CandidateMigrationsSHA256,
		RequestSHA256:                result.RequestSHA256,
		BinarySHA256:                 result.BinarySHA256,
		Verified:                     true,
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	return publishRetainedPrimaryReceipt(in.Directory, encoded)
}

func validateRetainedPrimaryRebuild(in retainedPrimaryRebuildInput) error {
	fail := errors.New("retained_primary_inputs_invalid")
	if in.BridgeOnly != (in.RetainedExit != nil) || (in.RetainedExit != nil && !in.RetainedExit.valid()) {
		return errors.New("retained_bridge_scope_invalid")
	}
	for _, value := range []string{in.JournalSHA256, in.ConfigSHA256, in.ManifestSHA256, in.Primary.MigrationsSHA256, in.CandidateMigrationsSHA256, in.FenceEvidenceSHA256} {
		if !rebuildSHA.MatchString(value) {
			return fail
		}
	}
	if in.CandidateMigrationsSHA256 != in.Primary.MigrationsSHA256 ||
		in.CandidateMigrationVersions != in.Primary.MigrationVersions ||
		!retainedMigrationVersionsCanonical(in.CandidateMigrationVersions) ||
		digestSHA256([]byte(in.CandidateMigrationVersions)) != in.CandidateMigrationsSHA256 {
		return errors.New("retained_primary_candidate_migrations_mismatch")
	}
	id, err := strconv.ParseUint(in.Primary.SystemIdentifier, 10, 64)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != in.Primary.SystemIdentifier || in.Primary.DatabaseOID == 0 ||
		!rebuildLabel.MatchString(in.Primary.Database) {
		return fail
	}
	for _, path := range []string{in.Directory, in.Python, in.Executable} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fail
		}
	}
	if rebuildNoSymlinkAncestors(in.Directory) != nil {
		return fail
	}
	info, err := os.Lstat(in.Directory)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		return fail
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fail
	}
	all, _ := in.Inventory["all"].(map[string]any)
	children, _ := all["children"].(map[string]any)
	if len(children) != 3 {
		return fail
	}
	addresses := map[string]bool{}
	for _, scope := range []struct{ group, host string }{{"bridge", "bridge"}, {"exits", "exit_0"}, {"databases", "database"}} {
		group, _ := children[scope.group].(map[string]any)
		hosts, _ := group["hosts"].(map[string]any)
		host, _ := hosts[scope.host].(map[string]any)
		address, _ := host["ansible_host"].(string)
		if len(hosts) != 1 || net.ParseIP(address) == nil || addresses[address] {
			return fail
		}
		addresses[address] = true
	}
	// No import/provisioning declaration is meaningful on this execution path.
	if retainedPrimaryForbiddenVariables(in.Inventory) || retainedPrimaryForbiddenVariables(in.Variables) {
		return fail
	}
	source, _ := in.Variables["ultra_db_tunnel_private_key_source"].(string)
	keySHA, _ := in.Variables["ultra_db_tunnel_private_key_sha256"].(string)
	if !filepath.IsAbs(source) || filepath.Clean(source) != source || !rebuildSHA.MatchString(keySHA) {
		return fail
	}
	return nil
}

func retainedPrimaryForbiddenVariables(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if key == "ultra_postgres" || key == "ultra_postgres_replica" || key == "ultra_result_file" || key == "ultra_database_import" || strings.HasPrefix(key, "ultra_database_import_") {
				return true
			}
			if retainedPrimaryForbiddenVariables(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if retainedPrimaryForbiddenVariables(child) {
				return true
			}
		}
	}
	return false
}

func publishRetainedPrimaryReceipt(directory string, raw []byte) error {
	path := filepath.Join(directory, "retained-primary-receipt.json")
	if _, err := os.Lstat(path); err == nil {
		existing, err := readRebuildInput(path, true)
		if err != nil {
			return errors.New("retained_primary_receipt_unsafe")
		}
		if string(existing) == string(raw) {
			return nil
		}
		return errors.New("retained_primary_receipt_conflict")
	} else if !os.IsNotExist(err) {
		return errors.New("retained_primary_receipt_unsafe")
	}
	file, err := os.CreateTemp(directory, ".retained-primary-receipt-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(file.Name()) }()
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	// Linking is atomic and cannot overwrite another recovery's receipt.
	if err = os.Link(file.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	return dir.Sync()
}

// The identity wire format is the canonical ordered applied-version list, so
// equality checks every version; an opaque hash alone is not migration authority.
func retainedMigrationVersionsCanonical(value string) bool {
	if value == "" {
		return false
	}
	previous := uint64(0)
	for _, part := range strings.Split(value, ",") {
		version, err := strconv.ParseUint(part, 10, 32)
		if err != nil || version <= previous || strconv.FormatUint(version, 10) != part {
			return false
		}
		previous = version
	}
	return true
}
