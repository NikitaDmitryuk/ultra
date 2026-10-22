package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeRetainedBackupFixture(t *testing.T, root string, now time.Time, manifest retainedBackupManifest, extra bool) (string, string) {
	t.Helper()
	started, err := time.Parse("2006-01-02T15:04:05Z", manifest.SnapshotStartedUTC)
	if err != nil {
		t.Fatal(err)
	}
	archivePath := filepath.Join(root, "fixture.tar")
	archive, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(archive)
	manifestRaw, _ := json.Marshal(manifest)
	for _, item := range []struct {
		name string
		data []byte
	}{{"manifest.json", manifestRaw}, {"primary.dump", []byte("PGDMP fixture")}} {
		if err = writer.WriteHeader(&tar.Header{Name: item.name, Mode: 0600, Size: int64(len(item.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err = writer.Write(item.data); err != nil {
			t.Fatal(err)
		}
	}
	if extra {
		if err = writer.WriteHeader(&tar.Header{Name: "extra", Mode: 0600, Size: 0, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err = archive.Close(); err != nil {
		t.Fatal(err)
	}
	plain, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	stamp := started.Format("20060102T150405Z")
	path := filepath.Join(root, "primary-db-"+stamp+"-0123456789abcdef0123456789abcdef.backup.tar.age")
	if err = os.WriteFile(path, plain, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(path, now.Add(-time.Minute), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(plain)
	return path, hex.EncodeToString(sum[:])
}

func retainedBackupFixtureManifest() retainedBackupManifest {
	dumpHash := sha256.Sum256([]byte("PGDMP fixture"))
	return retainedBackupManifest{
		Version: 1, SnapshotStartedUTC: "2026-10-23T10:00:00Z",
		SourceSHA256: retainedSourceSHA256("192.0.2.30", "fixture_db"), Database: "fixture_db",
		DumpSHA256: hex.EncodeToString(dumpHash[:]),
	}
}

func TestRetainedBackupManifestJSONMatchesExporterFieldOrder(t *testing.T) {
	manifest := retainedBackupFixtureManifest()
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	expected := fmt.Sprintf(
		`{"version":1,"snapshot_started_utc":"%s","source_sha256":"%s","database":"%s","dump_sha256":"%s"}`,
		manifest.SnapshotStartedUTC, manifest.SourceSHA256, manifest.Database, manifest.DumpSHA256,
	)
	if string(raw) != expected {
		t.Fatalf("Go manifest encoding differs from exporter contract: %s", raw)
	}
}

func TestOperatorExporterBundlePassesRetainedVerifier(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	outputDir := filepath.Join(root, "output")
	if err := os.Mkdir(outputDir, 0700); err != nil {
		t.Fatal(err)
	}
	writeProtectedFixture := func(path, contents string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(root, "ssh-key")
	identity := filepath.Join(root, "age-identity")
	config := filepath.Join(root, "install.config")
	pins := filepath.Join(outputDir, "bootstrap-known_hosts")
	writeProtectedFixture(key, "fixture ssh key")
	writeProtectedFixture(identity, "fixture age identity")
	writeProtectedFixture(config, "DATABASE_IP=192.0.2.30\nBRIDGE_IP=192.0.2.20\nDB_NAME=fixture_db\n"+
		"DATABASE_SSH_KEY="+key+"\nBRIDGE_SSH_KEY="+key+"\n")
	writeProtectedFixture(pins, "192.0.2.30 ssh-ed25519 fixture\n192.0.2.20 ssh-ed25519 fixture\n")
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	for name, script := range map[string]string{
		"age-keygen": "#!/bin/sh\necho age1fixture\n",
		"ssh-keygen": "#!/bin/sh\necho fixture-host-key\n",
		"ssh":        "#!/bin/sh\nprintf 'PGDMP cross-language fixture'\n",
		"age":        "#!/bin/sh\nif [ \"$1\" = \"-d\" ]; then for last do :; done; cat \"$last\"; else cat; fi\n",
		"pg_restore": "#!/bin/sh\n[ -s \"$2\" ]\n",
	} {
		path := filepath.Join(bin, name)
		if err := os.WriteFile(path, []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+oldPath)
	tool := filepath.Join("..", "..", "scripts", "operator-db-dump.py")
	command := exec.Command("python3", tool, "--config", config, "--identity", identity, "--output-dir", outputDir)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("fixture exporter failed: %v", err)
	}
	fields := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			fields[key] = value
		}
	}
	if fields["exit_code"] != "0" || fields["path"] == "" || fields["sha256"] == "" {
		t.Fatalf("exporter returned invalid fixture evidence: %v", fields)
	}
	previousUID := retainedBackupExpectedUID
	retainedBackupExpectedUID = func() uint32 { return uint32(os.Geteuid()) }
	t.Cleanup(func() { retainedBackupExpectedUID = previousUID })
	source := retainedSourceSHA256("192.0.2.30", "fixture_db")
	metadata, err := verifyRetainedBackupBundle(fields["path"], fields["sha256"], identity, source, "fixture_db",
		30*time.Minute, time.Now())
	if err != nil {
		t.Fatalf("Go verifier rejected exporter bundle: %v", err)
	}
	expectedDump := sha256.Sum256([]byte("PGDMP cross-language fixture"))
	if metadata.DumpSHA256 != hex.EncodeToString(expectedDump[:]) {
		t.Fatalf("unexpected verified dump hash: %s", metadata.DumpSHA256)
	}
}

func TestRetainedBackupBundleAttestationAndFreshness(t *testing.T) {
	now := time.Date(2026, 10, 23, 10, 5, 0, 0, time.UTC)
	decryptionNow := now
	previousClock := retainedBackupClock
	retainedBackupClock = func() time.Time { return decryptionNow }
	t.Cleanup(func() { retainedBackupClock = previousClock })
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(root, "identity")
	if err := os.WriteFile(identity, []byte("fixture identity"), 0600); err != nil {
		t.Fatal(err)
	}
	manifest := retainedBackupFixtureManifest()
	path, cipherSHA := writeRetainedBackupFixture(t, root, now, manifest, false)
	if err := os.Chtimes(path, now.Add(-3*time.Hour), now.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"age":        "#!/bin/sh\ncat\n",
		"pg_restore": "#!/bin/sh\n[ \"$1\" = \"--file=/dev/null\" ] && [ -s \"$2\" ]\n",
	} {
		tool := filepath.Join(bin, name)
		if err := os.WriteFile(tool, []byte(content), 0700); err != nil {
			t.Fatal(err)
		}
	}
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", bin+string(os.PathListSeparator)+oldPath)
	previousUID := retainedBackupExpectedUID
	retainedBackupExpectedUID = func() uint32 { return uint32(os.Geteuid()) }
	t.Cleanup(func() { retainedBackupExpectedUID = previousUID })
	metadata, err := verifyRetainedBackupBundle(path, cipherSHA, identity, manifest.SourceSHA256, manifest.Database,
		30*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Age != 5*time.Minute || metadata.DumpSHA256 != manifest.DumpSHA256 {
		t.Fatalf("unexpected metadata: %+v", metadata)
	}
	if err = revalidateRetainedBackupFreshness(metadata, 30*time.Minute, now); err != nil {
		t.Fatalf("fresh attestation rejected due only to old file mtime: %v", err)
	}
	decryptionNow = now.Add(26 * time.Minute)
	if _, err = verifyRetainedBackupBundle(path, cipherSHA, identity, manifest.SourceSHA256, manifest.Database,
		30*time.Minute, now); err == nil {
		t.Fatal("backup that expires during decryption passed")
	}
	decryptionNow = now.Add(30 * time.Minute)
	if err = revalidateRetainedBackupFreshness(metadata, 30*time.Minute, now.Add(30*time.Minute)); err == nil {
		t.Fatal("expired backup passed admission revalidation")
	}
}

func TestRetainedBackupRejectsUnattestedAndUnsafeBundles(t *testing.T) {
	now := time.Date(2026, 10, 23, 10, 5, 0, 0, time.UTC)
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(root, "identity")
	if err := os.WriteFile(identity, []byte("identity"), 0600); err != nil {
		t.Fatal(err)
	}
	previousUID := retainedBackupExpectedUID
	retainedBackupExpectedUID = func() uint32 { return uint32(os.Geteuid()) }
	t.Cleanup(func() { retainedBackupExpectedUID = previousUID })
	manifest := retainedBackupFixtureManifest()
	path, cipherSHA := writeRetainedBackupFixture(t, root, now, manifest, true)
	if _, err := verifyRetainedBackupBundle(path, cipherSHA, identity, manifest.SourceSHA256, manifest.Database,
		30*time.Minute, now); err == nil {
		t.Fatal("archive with extra member accepted")
	}
	legacy := filepath.Join(root, "primary-db-20261023T100000Z-0123456789abcdef0123456789abcdef.dump.age")
	if err := os.WriteFile(legacy, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyRetainedBackupBundle(legacy, strings.Repeat("a", 64), identity, manifest.SourceSHA256,
		manifest.Database, 30*time.Minute, now); err == nil || err.Error() != "retained_primary_backup_attestation_required" {
		t.Fatalf("legacy dump error = %v", err)
	}
}

func TestRetainedBackupRejectsFIFOAndSymlinkParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(root, "identity")
	if err := os.WriteFile(identity, []byte("identity"), 0600); err != nil {
		t.Fatal(err)
	}
	previousUID := retainedBackupExpectedUID
	retainedBackupExpectedUID = func() uint32 { return uint32(os.Geteuid()) }
	t.Cleanup(func() { retainedBackupExpectedUID = previousUID })
	now := time.Date(2026, 10, 23, 10, 5, 0, 0, time.UTC)
	manifest := retainedBackupFixtureManifest()
	fifo := filepath.Join(root, "primary-db-20261023T100000Z-0123456789abcdef0123456789abcdef.backup.tar.age")
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := verifyRetainedBackupBundle(fifo, strings.Repeat("a", 64), identity, manifest.SourceSHA256,
		manifest.Database, 30*time.Minute, now); err == nil {
		t.Fatal("FIFO accepted as backup")
	}
	if time.Since(started) > time.Second {
		t.Fatal("FIFO open blocked")
	}
	if err := os.Remove(fifo); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	path, cipherSHA := writeRetainedBackupFixture(t, root, now, manifest, false)
	aliasPath := filepath.Join(alias, filepath.Base(path))
	if _, err := verifyRetainedBackupBundle(aliasPath, cipherSHA, identity, manifest.SourceSHA256,
		manifest.Database, 30*time.Minute, now); err == nil {
		t.Fatal("symlink parent accepted")
	}
}
