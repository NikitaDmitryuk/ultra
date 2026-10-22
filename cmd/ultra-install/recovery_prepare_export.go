package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/crypto/ssh"
)

type recoveryInputSources struct {
	RetainedDirectory string `json:"retained_directory"`
	BaselineRelease   string `json:"baseline_release"`
	OriginalConfig    string `json:"original_config"`
	OriginalJournal   string `json:"original_journal"`
	LegacyJournal     string `json:"legacy_journal"`
}

// Export copies only the evidence used by verification. In particular it never
// walks operator credentials, subscription keys or the entire retained workspace.
func recoveryInputExportPlan(s recoveryInputSources, pins, destination, toolsSHA string) (recoveryInputSnapshot, map[string]string, error) {
	var snapshot recoveryInputSnapshot
	paths := map[string]string{}
	for _, p := range []string{s.RetainedDirectory, s.BaselineRelease, s.OriginalConfig, s.OriginalJournal, s.LegacyJournal, pins} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return snapshot, nil, errors.New("recovery_inputs_source_path_invalid")
		}
	}
	preparedRaw, err := readRebuildInput(filepath.Join(s.RetainedDirectory, "prepared-input.json"), true)
	var original retainedPrimaryRebuildInput
	if err != nil || decodeRetainedReconcile(preparedRaw, &original) != nil {
		return snapshot, nil, errors.New("recovery_inputs_prepared_invalid")
	}
	all, _ := original.Inventory["all"].(map[string]any)
	groups, _ := all["children"].(map[string]any)
	bridge, _ := groups["bridge"].(map[string]any)
	hosts, _ := bridge["hosts"].(map[string]any)
	host, _ := hosts["bridge"].(map[string]any)
	relay, _ := host["ultra_relay_source"].(string)
	if !filepath.IsAbs(relay) {
		return snapshot, nil, errors.New("recovery_inputs_baseline_source_invalid")
	}
	sourceRequest := recoveryPreparationRequest{
		RetainedDirectory:       s.RetainedDirectory,
		EvidenceSourceDirectory: original.Directory,
		BaselineSourceDirectory: filepath.Dir(relay),
		ConfigPath:              s.OriginalConfig,
		BaselineManifestPath:    filepath.Join(s.BaselineRelease, "release-manifest.json"),
		OriginalJournalPath:     s.OriginalJournal,
	}
	verified, err := loadRecoveryPreparationRetainedEvidence(sourceRequest)
	if err != nil {
		return snapshot, nil, err
	}
	legacy, err := readRebuildInput(s.LegacyJournal, true)
	if err != nil {
		return snapshot, nil, err
	}
	if _, err = parseBridgePreflightJournal(legacy); err != nil {
		return snapshot, nil, err
	}
	pinBytes, err := readRebuildInput(pins, false)
	if err != nil {
		return snapshot, nil, err
	}
	remaining := pinBytes
	keys := 0
	for len(strings.TrimSpace(string(remaining))) > 0 {
		_, _, _, _, rest, parseErr := ssh.ParseKnownHosts(remaining)
		if parseErr != nil {
			return snapshot, nil, errors.New("recovery_inputs_public_pins_invalid")
		}
		keys++
		remaining = rest
	}
	if keys == 0 {
		return snapshot, nil, errors.New("recovery_inputs_public_pins_required")
	}
	r := sourceRequest
	r.Protocol = "ultra-recovery-preparation-request-v1"
	r.RetainedDirectory = filepath.Join(destination, "retained")
	r.ConfigPath = filepath.Join(destination, "original.config")
	r.BaselineManifestPath = filepath.Join(destination, "baseline/release-manifest.json")
	r.OriginalJournalPath = filepath.Join(destination, "original-journal.json")
	r.LegacyJournalPath = filepath.Join(destination, "legacy-journal.json")
	r.KnownHostsPath = filepath.Join(destination, "known_hosts")
	r.UpgradeConfigPath = filepath.Join(filepath.Dir(destination), "install.config")
	r.ToolsReleaseDirectory = filepath.Join(filepath.Dir(destination), "release")
	r.ConfigSHA256 = verified.admission.ConfigSHA256
	r.BaselineManifestSHA256 = verified.admission.BaselineManifestSHA256
	r.RetainedFenceSHA256 = verified.admission.FenceSHA256
	r.LegacyJournalSHA256 = digestSHA256(legacy)
	r.KnownHostsSHA256 = digestSHA256(pinBytes)
	r.ToolsManifestSHA256 = toolsSHA
	r.StateDirectory = filepath.Join("/var/lib/ultra-ansible/recovery-preparation", r.LegacyJournalSHA256+"-"+toolsSHA)
	snapshot = recoveryInputSnapshot{Schema: 1, Request: r, Entries: map[string]recoveryInputEntry{}}
	add := func(name, source string) error {
		if !recoveryInputPath(name) {
			return errors.New("recovery_inputs_source_inventory_invalid")
		}
		for current := source; ; current = filepath.Dir(current) {
			info, e := os.Lstat(current)
			if e != nil {
				return e
			}
			if info.Mode()&os.ModeSymlink != 0 {
				return errors.New("recovery_inputs_source_symlink")
			}
			if filepath.Dir(current) == current {
				break
			}
		}
		info, e := os.Lstat(source)
		if e != nil {
			return e
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0022 != 0 {
			return errors.New("recovery_inputs_source_unsafe")
		}
		entry := recoveryInputEntry{Mode: uint32(info.Mode().Perm())}
		if info.IsDir() {
			entry.Kind = "directory"
		} else {
			if !info.Mode().IsRegular() || owner.Nlink != 1 {
				return errors.New("recovery_inputs_source_unsafe")
			}
			entry.Kind = "file"
			entry.Size = info.Size()
			entry.SHA256, e = sourceSHA(source)
			if e != nil {
				return e
			}
			paths[name] = source
		}
		snapshot.Entries[name] = entry
		return nil
	}
	for name, source := range map[string]string{"original.config": s.OriginalConfig, "original-journal.json": s.OriginalJournal, "legacy-journal.json": s.LegacyJournal, "known_hosts": pins, "retained/prepared-input.json": filepath.Join(s.RetainedDirectory, "prepared-input.json")} {
		if err = add(name, source); err != nil {
			return snapshot, nil, err
		}
	}
	for _, name := range []string{"retained", "retained/execute", "retained/execute/bundle", "baseline"} {
		snapshot.Entries[name] = recoveryInputEntry{Kind: "directory", Mode: 0700}
	}
	for _, name := range []string{"request.json", "job.json", "receipt.json", "result.json", "bundle.retention.json"} {
		if err = add("retained/execute/"+name, filepath.Join(s.RetainedDirectory, "execute", name)); err != nil {
			return snapshot, nil, err
		}
	}
	bundle := filepath.Join(s.RetainedDirectory, "execute/bundle")
	err = filepath.WalkDir(bundle, func(p string, _ os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if p == bundle {
			return nil
		}
		relative, _ := filepath.Rel(bundle, p)
		return add("retained/execute/bundle/"+filepath.ToSlash(relative), p)
	})
	if err != nil {
		return snapshot, nil, err
	}
	manifest, err := verifyAutomationRelease(s.BaselineRelease, "")
	if err != nil {
		return snapshot, nil, err
	}
	if err = add("baseline/release-manifest.json", filepath.Join(s.BaselineRelease, "release-manifest.json")); err != nil {
		return snapshot, nil, err
	}
	for _, asset := range manifest.Assets {
		if err = add("baseline/"+asset.Name, filepath.Join(s.BaselineRelease, asset.Name)); err != nil {
			return snapshot, nil, err
		}
	}
	if err = validateRecoveryInputSnapshot(snapshot, destination); err != nil {
		return snapshot, nil, err
	}
	return snapshot, paths, nil
}

func writeRecoveryInputArchive(out io.Writer, snapshot recoveryInputSnapshot, paths map[string]string) error {
	compressor := gzip.NewWriter(out)
	archive := tar.NewWriter(compressor)
	raw, _ := json.Marshal(snapshot)
	if err := archive.WriteHeader(&tar.Header{Name: "descriptor.json", Mode: 0600, Size: int64(len(raw))}); err != nil {
		return err
	}
	if _, err := archive.Write(raw); err != nil {
		return err
	}
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry := snapshot.Entries[name]
		file, err := os.OpenFile(paths[name], os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return err
		}
		if !info.Mode().IsRegular() || info.Size() != entry.Size || uint32(info.Mode().Perm()) != entry.Mode {
			_ = file.Close()
			return errors.New("recovery_inputs_source_changed")
		}
		if err = archive.WriteHeader(&tar.Header{Name: name, Mode: int64(entry.Mode), Size: entry.Size}); err != nil {
			_ = file.Close()
			return err
		}
		digest := sha256.New()
		_, err = io.CopyN(io.MultiWriter(archive, digest), file, entry.Size)
		after, statErr := file.Stat()
		closeErr := file.Close()
		if err != nil {
			return err
		}
		if statErr != nil {
			return statErr
		}
		if closeErr != nil {
			return closeErr
		}
		if after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) || hex.EncodeToString(digest.Sum(nil)) != entry.SHA256 {
			return errors.New("recovery_inputs_source_changed")
		}
	}
	if err := archive.Close(); err != nil {
		return err
	}
	return compressor.Close()
}

func runExportRecoveryInputs(_ context.Context, args []string, out io.Writer) error {
	fs := flag.NewFlagSet("deploy-operation export-preparation", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	spec := fs.String("source-spec", "", "private source path inventory")
	destination := fs.String("remote-directory", "", "fixed candidate preparation directory")
	pins := fs.String("known-hosts", "", "accepted public SSH pins")
	toolsSHA := fs.String("tools-manifest-sha256", "", "candidate tools manifest digest")
	if fs.Parse(args) != nil || fs.NArg() != 0 || !runtimeHostValidDigest(*toolsSHA) ||
		!regexp.MustCompile(`^/var/lib/ultra-ansible/operator-inputs/manual-[a-f0-9]{40}-[a-f0-9]{64}/preparation$`).
			MatchString(*destination) {
		return errors.New("recovery_inputs_export_arguments_invalid")
	}
	raw, err := readRebuildInput(*spec, true)
	var sources recoveryInputSources
	if err != nil || decodeRetainedReconcile(raw, &sources) != nil {
		return errors.New("recovery_inputs_sources_invalid")
	}
	snapshot, paths, err := recoveryInputExportPlan(sources, *pins, *destination, *toolsSHA)
	if err != nil {
		return err
	}
	return writeRecoveryInputArchive(out, snapshot, paths)
}
