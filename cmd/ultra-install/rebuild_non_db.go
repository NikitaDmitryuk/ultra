package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type rebuildPreflightRecord struct {
	Protocol                    string   `json:"protocol"`
	State                       string   `json:"state"`
	OperationID                 string   `json:"operation_id"`
	EnvelopeSHA                 string   `json:"envelope_sha256"`
	JournalSHA                  string   `json:"original_journal_sha256"`
	ConfigSHA                   string   `json:"config_sha256"`
	ManifestSHA                 string   `json:"manifest_sha256"`
	Envelope                    []byte   `json:"unverified_envelope"`
	FleetVerified               bool     `json:"fleet_verified"`
	PrimaryVerified             bool     `json:"primary_verified"`
	PrimaryConnectivityVerified bool     `json:"primary_connectivity_verified"`
	BackupVerified              bool     `json:"backup_verified"`
	FormerTargetsReimaged       bool     `json:"former_targets_reimaged"`
	JournalRetirementSupported  bool     `json:"journal_retirement_supported"`
	ExecutionSupported          bool     `json:"execution_supported"`
	GateReleased                bool     `json:"gate_released"`
	Blockers                    []string `json:"blockers"`
}

var errRebuildBlocked = errors.New("rebuild_non_db_preflight_blocked")

// No execute/resume action is registered. A preflight record cannot become a
// completion receipt or authorize a broker reservation or ordinary deployment.
func runRebuildNonDB(args []string, output io.Writer, now time.Time) error {
	if len(args) > 0 && args[0] == "diagnose" {
		return diagnoseRebuildNonDB(args[1:], output)
	}
	if len(args) == 0 || args[0] != "preflight" {
		return errors.New("rebuild_non_db_execution_not_supported")
	}
	flags := flag.NewFlagSet("rebuild-non-db preflight", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	proofPath := flags.String("proof", "", "unverified private evidence envelope")
	journalPath := flags.String("original-journal", "", "original manual journal (read only)")
	configPath := flags.String("config", "", "canonical install.config (read only)")
	manifestPath := flags.String("manifest", "", "candidate release manifest (read only)")
	statePath := flags.String("state-dir", "", "existing empty private directory for blocked evidence intake")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 {
		return errors.New("rebuild_non_db_arguments_invalid")
	}
	paths := []string{*proofPath, *journalPath, *configPath, *manifestPath, *statePath}
	seen := map[string]bool{}
	for _, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || seen[path] {
			return errors.New("rebuild_non_db_paths_invalid")
		}
		seen[path] = true
	}
	proofRaw, err := readRebuildInput(*proofPath, true)
	if err != nil {
		return err
	}
	journalRaw, err := readRebuildInput(*journalPath, true)
	if err != nil {
		return err
	}
	configRaw, err := readRebuildInput(*configPath, true)
	if err != nil {
		return err
	}
	manifestRaw, err := readRebuildInput(*manifestPath, false)
	if err != nil {
		return err
	}
	if !json.Valid(journalRaw) || !json.Valid(manifestRaw) {
		return errors.New("rebuild_non_db_inputs_invalid")
	}
	proof, err := validateRebuildEvidence(proofRaw, now, digestSHA256(journalRaw), digestSHA256(configRaw), digestSHA256(manifestRaw))
	if err != nil {
		return err
	}
	record := rebuildPreflightRecord{
		Protocol: rebuildPreflightProtocol, State: "blocked-unverified", OperationID: proof.OperationID,
		EnvelopeSHA: digestSHA256(proofRaw), JournalSHA: proof.JournalSHA, ConfigSHA: proof.ConfigSHA,
		ManifestSHA: proof.ManifestSHA, Envelope: proofRaw,
		Blockers: []string{
			"collector_authority_not_bound",
			"independent_live_collection_not_run",
			"controller_fence_import_not_implemented",
			"former_target_reimage_not_verified",
			"independent_backup_receipt_not_verified",
			"retained_primary_connectivity_not_verified",
			"journal_retirement_not_implemented",
			"rebuild_execution_not_implemented",
		},
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err = persistBlockedRebuild(*statePath, raw); err != nil {
		return err
	}
	// Output contains no proof, topology, database identity or configuration.
	record.Envelope = nil
	if err = json.NewEncoder(output).Encode(record); err != nil {
		return err
	}
	return errRebuildBlocked
}

func readRebuildInput(path string, private bool) ([]byte, error) {
	fail := errors.New("rebuild_non_db_input_not_safe")
	if err := rebuildNoSymlinkAncestors(path); err != nil {
		return nil, fail
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fail
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close() //nolint:errcheck
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return nil, fail
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 ||
		(private && info.Mode().Perm() != 0600) {
		return nil, fail
	}
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return nil, fail
	}
	return raw, nil
}

func rebuildNoSymlinkAncestors(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("rebuild_non_db_symlink_forbidden")
		}
		if filepath.Dir(current) == current {
			return nil
		}
	}
}

// Publish one non-overwriting blocked intake record, never an execution
// checkpoint. Crashed temporary publications or unknown stage files fail closed.
func persistBlockedRebuild(directory string, raw []byte) error {
	if operatorPrivate(directory, true) != nil {
		return errors.New("rebuild_non_db_private_state_required")
	}
	fd, err := syscall.Open(directory, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), directory)
	defer dir.Close() //nolint:errcheck
	lockFD, err := syscall.Openat(
		fd,
		".rebuild-preflight.lock",
		syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC,
		0600,
	)
	if err != nil {
		return err
	}
	lock := os.NewFile(uintptr(lockFD), "rebuild lock")
	defer lock.Close() //nolint:errcheck
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return errors.New("rebuild_non_db_lock_invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || syscall.Flock(lockFD, syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		return errors.New("rebuild_non_db_state_busy_or_invalid")
	}
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return err
	}
	const name = "rebuild-preflight.json"
	for _, entry := range entries {
		if entry.Name() != name && entry.Name() != ".rebuild-preflight.lock" {
			return errors.New("rebuild_non_db_unknown_checkpoint")
		}
	}
	existingFD, err := syscall.Openat(fd, name, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err == nil {
		existing := os.NewFile(uintptr(existingFD), name)
		defer existing.Close() //nolint:errcheck
		info, statErr := existing.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			return errors.New("rebuild_non_db_state_changed")
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
			return errors.New("rebuild_non_db_state_changed")
		}
		before, readErr := io.ReadAll(io.LimitReader(existing, (2<<20)+1))
		if readErr != nil || !bytes.Equal(before, raw) {
			return errors.New("rebuild_non_db_state_changed")
		}
		return dir.Sync()
	}
	if !errors.Is(err, syscall.ENOENT) {
		return errors.New("rebuild_non_db_state_changed")
	}
	// The fixed temporary name is opened exclusively under the held directory
	// descriptor. A crash artifact is deliberately not recovered or overwritten.
	temporary := ".rebuild-preflight-pending"
	tmpFD, err := syscall.Openat(fd, temporary, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(tmpFD), temporary)
	_, err = file.Write(raw)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	// Publish exclusively even if an unexpected writer ignored the lock.
	if err = unix.Renameat2(fd, temporary, fd, name, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	if err = dir.Sync(); err != nil {
		return fmt.Errorf("rebuild_non_db_state_sync_failed: %w", err)
	}
	return nil
}
