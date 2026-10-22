package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
)

// The transport manifest describes an immutable copy, not a replacement for
// retained-primary evidence. Original source paths remain in authenticated JSON.
type recoveryInputEntry struct {
	Kind   string `json:"kind"`
	Mode   uint32 `json:"mode"`
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}
type recoveryInputSnapshot struct {
	Schema  int                           `json:"schema"`
	Request recoveryPreparationRequest    `json:"request"`
	Entries map[string]recoveryInputEntry `json:"entries"`
}

func recoveryInputPath(name string) bool {
	if name == "" || path.Clean(name) != name || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") {
		return false
	}
	for _, part := range strings.Split(name, "/") {
		if part == "." || part == ".." || strings.HasPrefix(part, ".") {
			return false
		}
	}
	switch name {
	case "original.config",
		"original-journal.json",
		"legacy-journal.json",
		"known_hosts",
		"retained",
		"retained/execute",
		"retained/execute/bundle",
		"baseline",
		"retained/prepared-input.json",
		"retained/execute/request.json",
		"retained/execute/job.json",
		"retained/execute/receipt.json",
		"retained/execute/result.json",
		"retained/execute/bundle.retention.json":
		return true
	}
	return strings.HasPrefix(name, "retained/execute/bundle/") || (strings.HasPrefix(name, "baseline/") && strings.Count(name, "/") == 1)
}

func recoverySnapshotRequestRoots(r recoveryPreparationRequest, root string) bool {
	return r.RetainedDirectory == filepath.Join(root, "retained") && r.ConfigPath == filepath.Join(root, "original.config") &&
		r.OriginalJournalPath == filepath.Join(
			root,
			"original-journal.json",
		) && r.LegacyJournalPath == filepath.Join(root, "legacy-journal.json") &&
		r.KnownHostsPath == filepath.Join(
			root,
			"known_hosts",
		) && r.BaselineManifestPath == filepath.Join(root, "baseline/release-manifest.json") &&
		r.ToolsReleaseDirectory == filepath.Join(
			filepath.Dir(root),
			"release",
		) && r.UpgradeConfigPath == filepath.Join(filepath.Dir(root), "install.config")
}

func validateRecoveryInputSnapshot(snapshot recoveryInputSnapshot, root string) error {
	if snapshot.Schema != 1 || len(snapshot.Entries) == 0 || len(snapshot.Entries) > 20000 ||
		!recoverySnapshotRequestRoots(snapshot.Request, root) {
		return errors.New("recovery_inputs_manifest_invalid")
	}
	var total int64
	for name, entry := range snapshot.Entries {
		if !recoveryInputPath(name) || entry.Mode & ^uint32(0755) != 0 || entry.Mode&0022 != 0 || entry.Mode&0400 == 0 {
			return errors.New("recovery_inputs_path_invalid")
		}
		switch entry.Kind {
		case "directory":
			if entry.Mode&0100 == 0 || entry.Size != 0 || entry.SHA256 != "" {
				return errors.New("recovery_inputs_directory_invalid")
			}
		case "file":
			if entry.Size < 0 || entry.Size > 1<<30 || !runtimeHostValidDigest(entry.SHA256) {
				return errors.New("recovery_inputs_file_invalid")
			}
			total += entry.Size
			if total > 3<<30 {
				return errors.New("recovery_inputs_size_limit")
			}
		default:
			return errors.New("recovery_inputs_kind_invalid")
		}
		parent := path.Dir(name)
		for parent != "." {
			if snapshot.Entries[parent].Kind != "directory" {
				return errors.New("recovery_inputs_parent_missing")
			}
			parent = path.Dir(parent)
		}
	}
	for _, required := range []string{"original.config", "original-journal.json", "legacy-journal.json", "known_hosts", "retained/prepared-input.json", "retained/execute/request.json", "retained/execute/job.json", "retained/execute/receipt.json", "retained/execute/result.json", "retained/execute/bundle.retention.json", "baseline/release-manifest.json"} {
		if snapshot.Entries[required].Kind != "file" {
			return errors.New("recovery_inputs_incomplete")
		}
	}
	return nil
}

func readRecoveryInputSnapshot(stream io.Reader, root, descriptorSHA string) (recoveryInputSnapshot, *tar.Reader, *gzip.Reader, error) {
	var snapshot recoveryInputSnapshot
	gzipReader, err := gzip.NewReader(stream)
	if err != nil {
		return snapshot, nil, nil, errors.New("recovery_inputs_archive_invalid")
	}
	archive := tar.NewReader(gzipReader)
	header, err := archive.Next()
	if err != nil || header.Name != "descriptor.json" || header.Typeflag != tar.TypeReg || header.Size < 1 || header.Size > 8<<20 {
		_ = gzipReader.Close()
		return snapshot, nil, nil, errors.New("recovery_inputs_descriptor_invalid")
	}
	raw, err := io.ReadAll(io.LimitReader(archive, header.Size+1))
	if err != nil || int64(len(raw)) != header.Size || digestSHA256(raw) != descriptorSHA ||
		decodeRetainedReconcile(raw, &snapshot) != nil {
		_ = gzipReader.Close()
		return snapshot, nil, nil, errors.New("recovery_inputs_descriptor_changed")
	}
	if err = validateRecoveryInputSnapshot(snapshot, root); err != nil {
		_ = gzipReader.Close()
		return snapshot, nil, nil, err
	}
	return snapshot, archive, gzipReader, nil
}

// The destination is unpublished until every file, original evidence and mode
// has been checked. Replays compare the exact existing snapshot, never overwrite.
func importRecoveryInputs(stream io.Reader, root, descriptorSHA string) error {
	snapshot, archive, closer, err := readRecoveryInputSnapshot(stream, root, descriptorSHA)
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }()
	pending, err := os.MkdirTemp(filepath.Dir(root), ".preparation-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(pending) }()
	names := make([]string, 0, len(snapshot.Entries))
	for name := range snapshot.Entries {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := snapshot.Entries[name]
		if entry.Kind == "directory" {
			if err = os.MkdirAll(filepath.Join(pending, filepath.FromSlash(name)), 0700); err != nil {
				return err
			}
		}
	}
	seen := map[string]bool{}
	for {
		header, nextErr := archive.Next()
		if nextErr == io.EOF {
			break
		}
		if nextErr != nil {
			return errors.New("recovery_inputs_archive_invalid")
		}
		entry, ok := snapshot.Entries[header.Name]
		if !ok || entry.Kind != "file" || seen[header.Name] || header.Typeflag != tar.TypeReg || header.Size != entry.Size {
			return errors.New("recovery_inputs_archive_inventory_changed")
		}
		file, openErr := os.OpenFile(filepath.Join(pending, filepath.FromSlash(header.Name)), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if openErr != nil {
			return openErr
		}
		digest := sha256.New()
		_, err = io.CopyN(io.MultiWriter(file, digest), archive, entry.Size)
		if err == nil && hex.EncodeToString(digest.Sum(nil)) != entry.SHA256 {
			err = errors.New("recovery_inputs_file_changed")
		}
		if err == nil {
			err = file.Chmod(os.FileMode(entry.Mode))
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
		seen[header.Name] = true
	}
	// Consume bounded tar padding and the gzip trailer before publishing. A
	// truncated/corrupt transport or concatenated payload is not a snapshot.
	tail, tailErr := io.ReadAll(io.LimitReader(closer, 10241))
	if tailErr != nil || len(tail) > 10240 || len(bytes.Trim(tail, "\x00")) != 0 {
		return errors.New("recovery_inputs_archive_invalid")
	}
	for _, name := range names {
		entry := snapshot.Entries[name]
		if entry.Kind == "file" && !seen[name] {
			return errors.New("recovery_inputs_archive_incomplete")
		}
		if entry.Kind == "directory" {
			if err = os.Chmod(filepath.Join(pending, filepath.FromSlash(name)), os.FileMode(entry.Mode)); err != nil {
				return err
			}
		}
	}
	physical := snapshot.Request
	physical.RetainedDirectory = filepath.Join(pending, "retained")
	physical.ConfigPath = filepath.Join(pending, "original.config")
	physical.OriginalJournalPath = filepath.Join(pending, "original-journal.json")
	physical.BaselineManifestPath = filepath.Join(pending, "baseline/release-manifest.json")
	if _, err = loadRecoveryPreparationRetainedEvidence(physical); err != nil {
		return err
	}
	legacy, err := readRebuildInput(filepath.Join(pending, "legacy-journal.json"), true)
	if err != nil || digestSHA256(legacy) != snapshot.Request.LegacyJournalSHA256 {
		return errors.New("recovery_inputs_legacy_journal_changed")
	}
	if _, err = parseBridgePreflightJournal(legacy); err != nil {
		return err
	}
	pins, err := readRebuildInput(filepath.Join(pending, "known_hosts"), false)
	if err != nil || digestSHA256(pins) != snapshot.Request.KnownHostsSHA256 {
		return errors.New("recovery_inputs_pins_changed")
	}
	if err = saveDeployOperation(filepath.Join(pending, "preparation.json"), snapshot.Request); err != nil {
		return err
	}
	descriptor, _ := json.Marshal(snapshot)
	if err = writeUpgradeInput(filepath.Join(pending, "snapshot.json"), descriptor); err != nil {
		return err
	}
	for i := len(names) - 1; i >= 0; i-- {
		if snapshot.Entries[names[i]].Kind == "directory" {
			if err = syncUpgradeDirectory(filepath.Join(pending, filepath.FromSlash(names[i]))); err != nil {
				return err
			}
		}
	}
	if err = syncUpgradeDirectory(pending); err != nil {
		return err
	}
	if _, err = os.Lstat(root); err == nil {
		return compareRecoveryInputSnapshot(root, pending)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err = os.Rename(pending, root); err != nil {
		return err
	}
	return syncUpgradeDirectory(filepath.Dir(root))
}

func compareRecoveryInputSnapshot(root, pending string) error {
	expected := map[string]string{}
	collect := func(directory string, target map[string]string) error {
		return filepath.WalkDir(directory, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == directory {
				return operatorPrivate(p, true)
			}
			info, err := os.Lstat(p)
			if err != nil {
				return err
			}
			owner, ok := info.Sys().(*syscall.Stat_t)
			if !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 || (!info.IsDir() && owner.Nlink != 1) {
				return errors.New("recovery_inputs_existing_unsafe")
			}
			rel, _ := filepath.Rel(directory, p)
			if info.IsDir() {
				target[rel] = "directory:" + info.Mode().Perm().String()
				return nil
			}
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
				return errors.New("recovery_inputs_existing_unsafe")
			}
			hash, err := sourceSHA(p)
			if err != nil {
				return err
			}
			target[rel] = info.Mode().Perm().String() + ":" + hash
			return nil
		})
	}
	if err := collect(pending, expected); err != nil {
		return err
	}
	actual := map[string]string{}
	if err := collect(root, actual); err != nil {
		return err
	}
	a, _ := json.Marshal(expected)
	b, _ := json.Marshal(actual)
	if string(a) != string(b) {
		return errors.New("recovery_inputs_existing_changed")
	}
	return nil
}

func runImportRecoveryInputs(_ context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("deploy-operation import-preparation", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	directory := fs.String("directory", "", "fixed candidate preparation directory")
	digest := fs.String("descriptor-sha256", "", "transport manifest digest")
	if fs.Parse(args) != nil || fs.NArg() != 0 || os.Geteuid() != 0 || !runtimeHostValidDigest(*digest) ||
		!regexp.MustCompile(`^/var/lib/ultra-ansible/operator-inputs/manual-[a-f0-9]{40}-[a-f0-9]{64}/preparation$`).
			MatchString(*directory) {
		return errors.New("recovery_inputs_import_arguments_invalid")
	}
	if err := operatorPrivate(filepath.Dir(*directory), true); err != nil {
		return err
	}
	if err := importRecoveryInputs(os.Stdin, *directory, *digest); err != nil {
		return err
	}
	raw, err := readRebuildInput(filepath.Join(*directory, "preparation.json"), true)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).
		Encode(map[string]string{"preparation_file": filepath.Join(*directory, "preparation.json"), "preparation_sha256": digestSHA256(raw)})
}
