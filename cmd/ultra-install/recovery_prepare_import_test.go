package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func recoveryInputFixture(root string) recoveryInputSnapshot {
	r := recoveryPreparationRequest{
		RetainedDirectory:     filepath.Join(root, "retained"),
		ConfigPath:            filepath.Join(root, "original.config"),
		OriginalJournalPath:   filepath.Join(root, "original-journal.json"),
		LegacyJournalPath:     filepath.Join(root, "legacy-journal.json"),
		KnownHostsPath:        filepath.Join(root, "known_hosts"),
		BaselineManifestPath:  filepath.Join(root, "baseline/release-manifest.json"),
		ToolsReleaseDirectory: filepath.Join(filepath.Dir(root), "release"),
		UpgradeConfigPath:     filepath.Join(filepath.Dir(root), "install.config"),
	}
	entries := map[string]recoveryInputEntry{}
	for _, name := range []string{"retained", "retained/execute", "retained/execute/bundle", "baseline"} {
		entries[name] = recoveryInputEntry{Kind: "directory", Mode: 0700}
	}
	for _, name := range []string{"original.config", "original-journal.json", "legacy-journal.json", "known_hosts", "retained/prepared-input.json", "retained/execute/request.json", "retained/execute/job.json", "retained/execute/receipt.json", "retained/execute/result.json", "retained/execute/bundle.retention.json", "baseline/release-manifest.json"} {
		entries[name] = recoveryInputEntry{Kind: "file", Mode: 0600, Size: 1, SHA256: digestSHA256([]byte("x"))}
	}
	return recoveryInputSnapshot{1, r, entries}
}
func recoveryInputArchive(t *testing.T, snapshot recoveryInputSnapshot, header *tar.Header, content []byte) ([]byte, string) {
	t.Helper()
	var out bytes.Buffer
	gzipWriter := gzip.NewWriter(&out)
	archive := tar.NewWriter(gzipWriter)
	descriptor, _ := json.Marshal(snapshot)
	if err := archive.WriteHeader(&tar.Header{Name: "descriptor.json", Mode: 0600, Size: int64(len(descriptor))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(descriptor); err != nil {
		t.Fatal(err)
	}
	if header != nil {
		if err := archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), digestSHA256(descriptor)
}
func TestRecoveryInputsRejectPathModeRootAndInventoryTampering(t *testing.T) {
	root := filepath.Join(t.TempDir(), "preparation")
	for _, attack := range []string{"traversal", "absolute", "hidden", "backslash", "writable", "missing-parent", "swapped-root", "missing-file"} {
		t.Run(attack, func(t *testing.T) {
			snapshot := recoveryInputFixture(root)
			switch attack {
			case "traversal":
				snapshot.Entries["retained/execute/bundle/../../escaped"] = recoveryInputEntry{
					Kind:   "file",
					Mode:   0600,
					SHA256: strings.Repeat("a", 64),
				}
			case "absolute":
				snapshot.Entries["/tmp/escaped"] = recoveryInputEntry{Kind: "directory", Mode: 0700}
			case "hidden":
				snapshot.Entries["retained/execute/bundle/.env"] = recoveryInputEntry{
					Kind:   "file",
					Mode:   0600,
					SHA256: strings.Repeat("a", 64),
				}
			case "backslash":
				snapshot.Entries[`retained/execute/bundle/a\b`] = recoveryInputEntry{Kind: "directory", Mode: 0700}
			case "writable":
				snapshot.Entries["retained"] = recoveryInputEntry{Kind: "directory", Mode: 0777}
			case "missing-parent":
				snapshot.Entries["retained/execute/bundle/absent/file"] = recoveryInputEntry{
					Kind:   "file",
					Mode:   0600,
					SHA256: strings.Repeat("a", 64),
				}
			case "swapped-root":
				snapshot.Request.ConfigPath = filepath.Join(filepath.Dir(root), "foreign.config")
			case "missing-file":
				delete(snapshot.Entries, "original.config")
			}
			if err := validateRecoveryInputSnapshot(snapshot, root); err == nil {
				t.Fatal("malicious manifest accepted")
			}
		})
	}
}
func TestRecoveryInputsArchiveFailureNeverPublishesDestination(t *testing.T) {
	for _, attack := range []string{"descriptor-digest", "symlink", "traversal", "absolute", "unlisted", "changed-file", "incomplete"} {
		t.Run(attack, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "preparation")
			snapshot := recoveryInputFixture(root)
			header := &tar.Header{Name: "original.config", Mode: 0600, Size: 1}
			content := []byte("x")
			switch attack {
			case "symlink":
				header.Typeflag = tar.TypeSymlink
				header.Linkname = "/etc/passwd"
				header.Size = 0
				content = nil
			case "traversal":
				header.Name = "../../outside"
			case "absolute":
				header.Name = "/outside"
			case "unlisted":
				header.Name = "arbitrary"
			case "changed-file":
				content = []byte("y")
			case "incomplete":
				header = nil
				content = nil
			}
			raw, digest := recoveryInputArchive(t, snapshot, header, content)
			if attack == "descriptor-digest" {
				digest = strings.Repeat("0", 64)
			}
			if err := importRecoveryInputs(bytes.NewReader(raw), root, digest); err == nil {
				t.Fatal("invalid archive accepted")
			}
			if _, err := os.Lstat(root); !os.IsNotExist(err) {
				t.Fatalf("unverified snapshot published: %v", err)
			}
			pending, _ := filepath.Glob(filepath.Join(filepath.Dir(root), ".preparation-*"))
			if len(pending) != 0 {
				t.Fatal("temporary unverified snapshot retained")
			}
		})
	}
}

func TestRecoveryInputsArchiveParserReportsFailureStage(t *testing.T) {
	root := filepath.Join(t.TempDir(), "preparation")
	for _, test := range []struct {
		input []byte
		want  string
	}{{nil, "recovery_inputs_gzip_empty"}, {[]byte("x"), "recovery_inputs_gzip_truncated"},
		{[]byte("not gzip"), "recovery_inputs_gzip_magic_invalid"}} {
		if err := importRecoveryInputs(bytes.NewReader(test.input), root, strings.Repeat("a", 64)); err == nil ||
			err.Error() != test.want {
			t.Errorf("gzip header error for %q = %v, want %s", test.input, err, test.want)
		}
	}

	snapshot := recoveryInputFixture(root)
	var raw bytes.Buffer
	compressed := gzip.NewWriter(&raw)
	archive := tar.NewWriter(compressed)
	descriptor, _ := json.Marshal(snapshot)
	if err := archive.WriteHeader(&tar.Header{Name: "descriptor.json", Mode: 0600, Size: int64(len(descriptor))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(descriptor); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := compressed.Write([]byte("unexpected trailing data")); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := importRecoveryInputs(bytes.NewReader(raw.Bytes()), root, digestSHA256(descriptor)); err == nil ||
		err.Error() != "recovery_inputs_archive_trailer_invalid" {
		t.Fatalf("archive trailer error = %v", err)
	}
}

func TestRecoveryInputsExistingReplayRequiresIdenticalTree(t *testing.T) {
	root, pending := t.TempDir(), t.TempDir()
	for _, p := range []string{root, pending} {
		if err := os.Chmod(p, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "item"), []byte("same"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := compareRecoveryInputSnapshot(root, pending); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "item"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := compareRecoveryInputSnapshot(root, pending); err == nil {
		t.Fatal("mode drift accepted")
	}
	if err := os.Remove(filepath.Join(root, "item")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(pending, "item"), filepath.Join(root, "item")); err != nil {
		t.Fatal(err)
	}
	if err := compareRecoveryInputSnapshot(root, pending); err == nil {
		t.Fatal("symlink replay accepted")
	}
}

func TestRecoveryInputsPreservesReadOnlyOriginalReleaseModes(t *testing.T) {
	root := filepath.Join(t.TempDir(), "preparation")
	snapshot := recoveryInputFixture(root)
	for _, mode := range []uint32{0400, 0500} {
		snapshot.Entries["baseline/ultra-relay-linux-amd64"] = recoveryInputEntry{
			Kind:   "file",
			Mode:   mode,
			Size:   1,
			SHA256: digestSHA256([]byte("x")),
		}
		if err := validateRecoveryInputSnapshot(snapshot, root); err != nil {
			t.Fatalf("immutable release mode %o rejected: %v", mode, err)
		}
	}
}

// This opt-in check uses an operator's protected export, never a production DB
// or network. Ordinary CI fixtures above do not require private infrastructure.
func TestRecoveryInputsOriginalSnapshotRoundTrip(t *testing.T) {
	source := os.Getenv("ULTRA_TEST_RECOVERY_INPUT_ARCHIVE")
	if source == "" {
		t.Skip("protected original export not supplied")
	}
	if err := operatorPrivate(source, false); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close() //nolint:errcheck
	compressed, err := gzip.NewReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close() //nolint:errcheck
	original := tar.NewReader(compressed)
	header, err := original.Next()
	if err != nil || header.Name != "descriptor.json" || header.Size > 8<<20 {
		t.Fatal("invalid export descriptor", err)
	}
	raw, err := io.ReadAll(original)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot recoveryInputSnapshot
	if err = decodeRetainedReconcile(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(t.TempDir(), "preparation")
	r := &snapshot.Request
	r.RetainedDirectory = filepath.Join(root, "retained")
	r.ConfigPath = filepath.Join(root, "original.config")
	r.OriginalJournalPath = filepath.Join(root, "original-journal.json")
	r.LegacyJournalPath = filepath.Join(root, "legacy-journal.json")
	r.KnownHostsPath = filepath.Join(root, "known_hosts")
	r.BaselineManifestPath = filepath.Join(root, "baseline/release-manifest.json")
	r.ToolsReleaseDirectory = filepath.Join(filepath.Dir(root), "release")
	r.UpgradeConfigPath = filepath.Join(filepath.Dir(root), "install.config")
	transport, err := os.CreateTemp(t.TempDir(), "snapshot-")
	if err != nil {
		t.Fatal(err)
	}
	defer transport.Close() //nolint:errcheck
	writer := gzip.NewWriter(transport)
	archive := tar.NewWriter(writer)
	descriptor, _ := json.Marshal(snapshot)
	if err = archive.WriteHeader(&tar.Header{Name: "descriptor.json", Mode: 0600, Size: int64(len(descriptor))}); err != nil {
		t.Fatal(err)
	}
	if _, err = archive.Write(descriptor); err != nil {
		t.Fatal(err)
	}
	for {
		header, err = original.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if err = archive.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err = io.Copy(archive, original); err != nil {
			t.Fatal(err)
		}
	}
	if err = archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = transport.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err = importRecoveryInputs(transport, root, digestSHA256(descriptor)); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"retained/prepared-input.json", "retained/execute/request.json", "retained/execute/bundle.retention.json", "baseline/release-manifest.json"} {
		digest, e := sourceSHA(filepath.Join(root, filepath.FromSlash(name)))
		if e != nil || digest != snapshot.Entries[name].SHA256 {
			t.Fatalf("historical bytes changed: %s %v", name, e)
		}
	}
	if _, err = transport.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if err = importRecoveryInputs(transport, root, digestSHA256(descriptor)); err != nil {
		t.Fatal("exact replay rejected", err)
	}
}

func TestRecoveryInputsCorruptTrailerCannotPublish(t *testing.T) {
	root := filepath.Join(t.TempDir(), "preparation")
	raw, digest := recoveryInputArchive(t, recoveryInputFixture(root), nil, nil)
	raw[len(raw)-8] ^= 1
	err := importRecoveryInputs(bytes.NewReader(raw), root, digest)
	if err == nil || err.Error() != "recovery_inputs_archive_trailer_invalid" {
		t.Fatalf("corrupt gzip trailer accepted: %v", err)
	}
	if _, err = os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("corrupt transport published")
	}
}
