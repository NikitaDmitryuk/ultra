package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const retainedBackupManifestLimit = 1 << 20

var retainedBackupName = regexp.MustCompile(`^primary-db-(\d{8}T\d{6}Z)-([0-9a-f]{32})\.backup\.tar\.age$`)
var retainedBackupSHA = regexp.MustCompile(`^[0-9a-f]{64}$`)
var retainedBackupExpectedUID = func() uint32 { return 0 }
var retainedBackupClock = time.Now

type retainedBackupManifest struct {
	Version            int    `json:"version"`
	SnapshotStartedUTC string `json:"snapshot_started_utc"`
	SourceSHA256       string `json:"source_sha256"`
	Database           string `json:"database"`
	DumpSHA256         string `json:"dump_sha256"`
}

type retainedBackupMetadata struct {
	Path              string
	EncryptedSHA256   string
	IdentityPath      string
	ExpectedSourceSHA string
	ExpectedDatabase  string
	SnapshotStarted   time.Time
	Age               time.Duration
	DumpSHA256        string
}

// retainedSourceSHA256 binds the manifest to the database primary host and name.
func retainedSourceSHA256(databaseHost, databaseName string) string {
	sum := sha256.Sum256([]byte(databaseHost + "\x00" + databaseName))
	return hex.EncodeToString(sum[:])
}

func openRetainedProtectedFile(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("retained_backup_absolute_path_required")
	}
	if err := retainedBackupNoSymlinkAncestors(filepath.Dir(path)); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	var st syscall.Stat_t
	if err = syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG ||
		st.Uid != retainedBackupExpectedUID() || st.Nlink != 1 || st.Mode&0777 != 0600 {
		_ = f.Close()
		return nil, errors.New("retained_backup_protected_file_required")
	}
	return f, nil
}

func retainedBackupNoSymlinkAncestors(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("retained_backup_absolute_path_required")
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return errors.New("retained_backup_path_ancestor_unsafe")
		}
		if current == string(filepath.Separator) {
			return nil
		}
	}
}

func verifyRetainedBackupDirectory(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("retained_backup_absolute_path_required")
	}
	if err := retainedBackupNoSymlinkAncestors(path); err != nil {
		return err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer func() { _ = syscall.Close(fd) }()
	var st syscall.Stat_t
	if err = syscall.Fstat(fd, &st); err != nil || st.Mode&syscall.S_IFMT != syscall.S_IFDIR ||
		st.Uid != retainedBackupExpectedUID() || st.Mode&0777 != 0700 {
		return errors.New("retained_backup_protected_directory_required")
	}
	return nil
}

func verifyRetainedBackupTarLayout(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	for index, expected := range []string{"manifest.json", "primary.dump"} {
		header := make([]byte, 512)
		if _, err = io.ReadFull(file, header); err != nil {
			return errors.New("retained_primary_backup_archive_invalid")
		}
		if allZero(header) || strings.TrimRight(string(header[:100]), "\x00") != expected ||
			(header[156] != 0 && header[156] != tar.TypeReg) ||
			strings.TrimRight(string(header[157:257]), "\x00") != "" || strings.TrimRight(string(header[345:500]), "\x00") != "" {
			return errors.New("retained_primary_backup_archive_invalid")
		}
		checksum, parseErr := strconv.ParseUint(strings.Trim(string(header[148:156]), " \x00"), 8, 64)
		if parseErr != nil {
			return errors.New("retained_primary_backup_archive_invalid")
		}
		var sum uint64
		for offset, value := range header {
			if offset >= 148 && offset < 156 {
				sum += uint64(' ')
			} else {
				sum += uint64(value)
			}
		}
		if sum != checksum {
			return errors.New("retained_primary_backup_archive_invalid")
		}
		sizeRaw := strings.Trim(string(header[124:136]), " \x00")
		size, parseErr := strconv.ParseUint(sizeRaw, 8, 64)
		if parseErr != nil || (index == 0 && size > retainedBackupManifestLimit) {
			return errors.New("retained_primary_backup_archive_invalid")
		}
		if _, err = io.CopyN(io.Discard, file, int64(size)); err != nil {
			return errors.New("retained_primary_backup_archive_invalid")
		}
		padding := (512 - size%512) % 512
		pad := make([]byte, padding)
		if _, err = io.ReadFull(file, pad); err != nil || !allZero(pad) {
			return errors.New("retained_primary_backup_archive_invalid")
		}
	}
	end := make([]byte, 512)
	for i := 0; i < 2; i++ {
		if _, err = io.ReadFull(file, end); err != nil || !allZero(end) {
			return errors.New("retained_primary_backup_archive_invalid")
		}
	}
	trailing, err := io.ReadAll(file)
	if err != nil || !allZero(trailing) {
		return errors.New("retained_primary_backup_archive_invalid")
	}
	return nil
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func verifyRetainedBackupBundle(path, expectedCipherSHA, identityPath, expectedSourceSHA, expectedDatabase string,
	maxAge time.Duration, now time.Time) (retainedBackupMetadata, error) {
	var result retainedBackupMetadata
	if maxAge <= 0 || !retainedBackupSHA.MatchString(expectedCipherSHA) || !retainedBackupSHA.MatchString(expectedSourceSHA) ||
		expectedDatabase == "" {
		return result, errors.New("retained_primary_fresh_private_backup_required")
	}
	base := filepath.Base(path)
	match := retainedBackupName.FindStringSubmatch(base)
	if match == nil {
		return result, errors.New("retained_primary_backup_attestation_required")
	}
	filenameTime, err := time.Parse("20060102T150405Z", match[1])
	if err != nil {
		return result, errors.New("retained_primary_backup_filename_invalid")
	}
	if err = verifyRetainedBackupDirectory(filepath.Dir(path)); err != nil {
		return result, errors.New("retained_primary_fresh_private_backup_required")
	}
	backup, err := openRetainedProtectedFile(path)
	if err != nil {
		return result, errors.New("retained_primary_fresh_private_backup_required")
	}
	defer func() { _ = backup.Close() }()
	info, err := backup.Stat()
	if err != nil || info.Size() <= 0 || info.ModTime().After(now.Add(5*time.Minute)) {
		return result, errors.New("retained_primary_fresh_private_backup_required")
	}
	h := sha256.New()
	if _, err = io.Copy(h, backup); err != nil || hex.EncodeToString(h.Sum(nil)) != expectedCipherSHA {
		return result, errors.New("retained_primary_backup_digest_mismatch")
	}
	if _, err = backup.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	identity, err := openRetainedProtectedFile(identityPath)
	if err != nil {
		return result, errors.New("retained_primary_age_identity_invalid")
	}
	defer func() { _ = identity.Close() }()
	plain, err := os.CreateTemp("", "ultra-retained-backup-*.tar")
	if err != nil {
		return result, err
	}
	plainPath := plain.Name()
	defer func() { _ = os.Remove(plainPath) }()
	if err = plain.Chmod(0600); err != nil {
		_ = plain.Close()
		return result, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "age", "--decrypt", "--identity", "/proc/self/fd/3")
	cmd.Stdin = backup
	cmd.Stdout = plain
	cmd.ExtraFiles = []*os.File{identity}
	if err = cmd.Run(); err != nil {
		_ = plain.Close()
		return result, errors.New("retained_primary_backup_authentication_failed")
	}
	// Snapshot age is checked after full age authentication/decryption so the
	// two-minute decrypt timeout cannot make the admission decision stale.
	now = retainedBackupClock().UTC()
	if err = plain.Sync(); err != nil {
		_ = plain.Close()
		return result, err
	}
	if err = plain.Close(); err != nil {
		return result, err
	}
	if filenameTime.After(now.Add(5 * time.Minute)) {
		return result, errors.New("retained_primary_backup_timestamp_invalid")
	}
	archive, err := os.Open(plainPath)
	if err != nil {
		return result, err
	}
	if err = verifyRetainedBackupTarLayout(plainPath); err != nil {
		_ = archive.Close()
		return result, err
	}
	reader := tar.NewReader(archive)
	manifestHeader, err := reader.Next()
	if err != nil || manifestHeader.Name != "manifest.json" || manifestHeader.Typeflag != tar.TypeReg ||
		manifestHeader.Size < 0 || manifestHeader.Size > retainedBackupManifestLimit {
		_ = archive.Close()
		return result, errors.New("retained_primary_backup_archive_invalid")
	}
	manifestRaw, err := io.ReadAll(io.LimitReader(reader, retainedBackupManifestLimit+1))
	if err != nil || int64(len(manifestRaw)) != manifestHeader.Size || len(manifestRaw) > retainedBackupManifestLimit {
		_ = archive.Close()
		return result, errors.New("retained_primary_backup_archive_invalid")
	}
	var manifest retainedBackupManifest
	decoder := json.NewDecoder(strings.NewReader(string(manifestRaw)))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&manifest); err != nil {
		_ = archive.Close()
		return result, errors.New("retained_primary_backup_manifest_invalid")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		_ = archive.Close()
		return result, errors.New("retained_primary_backup_manifest_invalid")
	}
	canonicalManifest, marshalErr := json.Marshal(manifest)
	if marshalErr != nil || !bytes.Equal(canonicalManifest, manifestRaw) {
		_ = archive.Close()
		return result, errors.New("retained_primary_backup_manifest_invalid")
	}
	started, err := time.Parse("2006-01-02T15:04:05Z", manifest.SnapshotStartedUTC)
	if err != nil || started.Format("2006-01-02T15:04:05Z") != manifest.SnapshotStartedUTC ||
		started.Format("20060102T150405Z") != match[1] || !started.Equal(filenameTime) ||
		started.After(now.Add(5*time.Minute)) || now.Sub(started) > maxAge || now.Sub(started) < -5*time.Minute {
		_ = archive.Close()
		return result, errors.New("retained_primary_backup_timestamp_invalid")
	}
	if manifest.Version != 1 || manifest.SourceSHA256 != expectedSourceSHA || manifest.Database != expectedDatabase ||
		!retainedBackupSHA.MatchString(manifest.DumpSHA256) {
		_ = archive.Close()
		return result, errors.New("retained_primary_backup_source_mismatch")
	}
	dumpHeader, err := reader.Next()
	if err != nil || dumpHeader.Name != "primary.dump" || dumpHeader.Typeflag != tar.TypeReg || dumpHeader.Size < 0 {
		_ = archive.Close()
		return result, errors.New("retained_primary_backup_archive_invalid")
	}
	dump, err := os.CreateTemp("", "ultra-retained-primary-*.dump")
	if err != nil {
		_ = archive.Close()
		return result, err
	}
	dumpPath := dump.Name()
	defer func() { _ = os.Remove(dumpPath) }()
	if err = dump.Chmod(0600); err != nil {
		_ = dump.Close()
		_ = archive.Close()
		return result, err
	}
	dumpHash := sha256.New()
	count, copyErr := io.Copy(io.MultiWriter(dump, dumpHash), reader)
	if copyErr != nil || count != dumpHeader.Size || hex.EncodeToString(dumpHash.Sum(nil)) != manifest.DumpSHA256 {
		_ = dump.Close()
		_ = archive.Close()
		return result, errors.New("retained_primary_backup_dump_digest_mismatch")
	}
	if err = dump.Sync(); err == nil {
		err = dump.Close()
	} else {
		_ = dump.Close()
	}
	if err != nil {
		_ = archive.Close()
		return result, err
	}
	if _, err = reader.Next(); err != io.EOF {
		_ = archive.Close()
		return result, errors.New("retained_primary_backup_archive_invalid")
	}
	if err = archive.Close(); err != nil {
		return result, err
	}
	cmd = exec.CommandContext(ctx, "pg_restore", "--file=/dev/null", dumpPath)
	if restoreErr := cmd.Run(); restoreErr != nil {
		return result, errors.New("retained_primary_backup_archive_invalid")
	}
	result = retainedBackupMetadata{
		Path: path, EncryptedSHA256: expectedCipherSHA, IdentityPath: identityPath,
		ExpectedSourceSHA: expectedSourceSHA, ExpectedDatabase: expectedDatabase,
		SnapshotStarted: started, Age: now.Sub(started), DumpSHA256: manifest.DumpSHA256,
	}
	return result, nil
}

func revalidateRetainedBackupFreshness(metadata retainedBackupMetadata, maxAge time.Duration, now time.Time) error {
	verified, err := verifyRetainedBackupBundle(metadata.Path, metadata.EncryptedSHA256, metadata.IdentityPath,
		metadata.ExpectedSourceSHA, metadata.ExpectedDatabase, maxAge, now)
	if err != nil {
		return err
	}
	if verified.DumpSHA256 != metadata.DumpSHA256 {
		return errors.New("retained_primary_backup_changed_after_verification")
	}
	return nil
}
