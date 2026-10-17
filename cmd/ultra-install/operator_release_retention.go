package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const operatorReleaseScanLimit = 8192
const operatorReleaseCandidateLimit = 32
const operatorReleaseByteLimit int64 = 8 << 30
const operatorReleasePinPrefix = ".operator-release-pin-"
const operatorReleasePinTempPrefix = ".ultra-operator-release-pin-tmp-"

type operatorReleasePin struct {
	OperationDir string `json:"operation_dir"`
	ReleaseDir   string `json:"release_dir"`
}

func operatorReleasePinPath(cache, operation, release string) (string, operatorReleasePin, error) {
	cache, err := filepath.Abs(cache)
	if err != nil {
		return "", operatorReleasePin{}, err
	}
	operation, err = filepath.Abs(operation)
	if err != nil {
		return "", operatorReleasePin{}, err
	}
	release, err = filepath.Abs(release)
	if err != nil {
		return "", operatorReleasePin{}, err
	}
	tag := strings.TrimPrefix(filepath.Base(release), "release-")
	if filepath.Dir(release) != cache || !stableReleaseTag.MatchString(tag) {
		return "", operatorReleasePin{}, errors.New("operator_release_pin_identity_invalid")
	}
	identity := sha256.Sum256([]byte(operation + "\x00" + release))
	name := operatorReleasePinPrefix + hex.EncodeToString(identity[:]) + ".json"
	return filepath.Join(cache, name), operatorReleasePin{OperationDir: operation, ReleaseDir: release}, nil
}

// Persist references centrally so a failed frozen operation protects its
// signed release even when --job-dir is outside the default operator tree.
func pinOperatorRelease(cache, operation, release string) (retErr error) {
	cacheAbs, err := filepath.Abs(cache)
	if err != nil {
		return err
	}
	releaseAbs, err := filepath.Abs(release)
	if err != nil {
		return err
	}
	if filepath.Dir(releaseAbs) != cacheAbs {
		return nil // External release directories are not candidates for this cache's collector.
	}
	path, expected, err := operatorReleasePinPath(cacheAbs, operation, releaseAbs)
	if err != nil {
		return err
	}
	cache = cacheAbs
	if err := operatorPrivate(cache, true); err != nil {
		return err
	}
	gate, err := lockReleaseCacheGate(cache)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := gate.Close(); closeErr != nil {
			retErr = errors.Join(retErr, closeErr)
		}
	}()
	if existing, err := readOperatorReleasePin(path); err == nil {
		if existing != expected {
			return errors.New("operator_release_pin_conflict")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	raw, err := json.Marshal(expected)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(cache, operatorReleasePinTempPrefix)
	if err != nil {
		return err
	}
	tempPath := file.Name()
	defer func() {
		if removeErr := os.Remove(tempPath); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			retErr = errors.Join(retErr, removeErr)
		}
	}()
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	written, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if written != len(raw) || writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.Join(writeErr, syncErr, closeErr, errors.New("operator_release_pin_write_incomplete"))
	}
	if err := os.Rename(tempPath, path); err != nil {
		return err
	}
	directory, err := os.Open(cache)
	if err != nil {
		return err
	}
	syncErr = directory.Sync()
	closeErr = directory.Close()
	if syncErr != nil || closeErr != nil {
		return errors.Join(syncErr, closeErr)
	}
	return nil
}

func unpinOperatorReleaseReferences(cache, operation string) (retErr error) {
	cache, err := filepath.Abs(cache)
	if err != nil {
		return err
	}
	operation, err = filepath.Abs(operation)
	if err != nil {
		return err
	}
	if err := operatorPrivate(cache, true); err != nil {
		return err
	}
	gate, err := lockReleaseCacheGate(cache)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := gate.Close(); closeErr != nil {
			retErr = errors.Join(retErr, closeErr)
		}
	}()
	pins, err := operatorReleasePinsLocked(cache)
	if err != nil {
		return err
	}
	for path, pin := range pins {
		if pin.OperationDir == operation {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func operatorReleasePinReferencesLocked(cache string) (map[string]bool, error) {
	pins, err := operatorReleasePinsLocked(cache)
	if err != nil {
		return nil, err
	}
	refs := make(map[string]bool, len(pins))
	for _, pin := range pins {
		refs[pin.ReleaseDir] = true
	}
	return refs, nil
}

func operatorReleasePinsLocked(cache string) (map[string]operatorReleasePin, error) {
	directory, err := os.Open(cache)
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(operatorReleaseScanLimit + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > operatorReleaseScanLimit {
		return nil, errors.New("operator_release_pin_scan_limit")
	}
	pins := map[string]operatorReleasePin{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), operatorReleasePinPrefix) {
			continue
		}
		path := filepath.Join(cache, entry.Name())
		pin, err := readOperatorReleasePin(path)
		if err != nil {
			return nil, err
		}
		want, expected, err := operatorReleasePinPath(cache, pin.OperationDir, pin.ReleaseDir)
		if err != nil || want != path || pin != expected {
			return nil, errors.New("operator_release_pin_invalid")
		}
		pins[path] = pin
	}
	return pins, nil
}

func readOperatorReleasePin(path string) (operatorReleasePin, error) {
	var pin operatorReleasePin
	if err := operatorPrivate(path, false); err != nil {
		return pin, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return pin, err
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Nlink != 1 || info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > 4096 {
		return pin, errors.New("operator_release_pin_metadata_invalid")
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &pin) != nil || pin.OperationDir == "" || pin.ReleaseDir == "" {
		return pin, errors.New("operator_release_pin_metadata_invalid")
	}
	return pin, nil
}

// Caller holds the exclusive operator lease. Per-bundle leases also protect
// preparers and users before request metadata exists. Keep includes current and
// rollback tags; metadata survives.
func pruneVerifiedOperatorReleaseCache(cacheDirectory, operatorRoot, publicKey, minisignPath string, keep ...string) error {
	if len(keep) == 0 || strings.TrimSpace(publicKey) == "" {
		return errors.New("operator_release_retention_identity_required")
	}
	versions := map[string]bool{}
	for _, tag := range keep {
		if !stableReleaseTag.MatchString(tag) {
			return errors.New("operator_release_retention_identity_invalid")
		}
		versions[tag] = true
	}
	if minisignPath == "" {
		minisignPath = "minisign"
	}
	cache, err := filepath.Abs(cacheDirectory)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(operatorRoot)
	if err != nil {
		return err
	}
	if err := operatorPrivate(root, true); err != nil {
		return err
	}
	if err := operatorPrivate(cache, true); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	refs, err := operatorReleaseLiveReferences(root, cache)
	if err != nil {
		return err
	}
	gate, err := lockReleaseCacheGate(cache)
	if err != nil {
		return err
	}
	pinRefs, pinErr := operatorReleasePinReferencesLocked(cache)
	gateErr := gate.Close()
	if pinErr != nil {
		return pinErr
	}
	if gateErr != nil {
		return gateErr
	}
	for ref := range pinRefs {
		refs[ref] = true
	}
	directory, err := os.Open(cache)
	if err != nil {
		return err
	}
	entries, readErr := directory.ReadDir(operatorReleaseScanLimit + 1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return readErr
	}
	if closeErr != nil {
		return closeErr
	}
	if len(entries) > operatorReleaseScanLimit {
		return errors.New("operator_release_retention_scan_limit")
	}
	candidates := 0
	var verifiedBytes int64
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "release-") {
			continue
		}
		tag := strings.TrimPrefix(entry.Name(), "release-")
		if !stableReleaseTag.MatchString(tag) || versions[tag] {
			continue
		}
		path := filepath.Join(cache, entry.Name())
		if operatorReleasePathReferenced(path, refs) {
			continue
		}
		err := func() (retErr error) {
			gate, err := lockReleaseCacheGate(cache)
			if err != nil {
				return err
			}
			locked, lockErr := lockReleaseDirectory(path, syscall.LOCK_EX|syscall.LOCK_NB)
			_ = gate.Close()
			if lockErr != nil {
				return nil
			} // In-use, vanished, or unsafe entry: preserve.
			defer func() {
				if closeErr := locked.Close(); closeErr != nil {
					retErr = errors.Join(retErr, closeErr)
				}
			}()
			lockedInfo, err := locked.Stat()
			if err != nil {
				return err
			}
			inventory, err := operatorReleaseCacheInventory(path)
			if err != nil {
				return nil
			}
			var candidateBytes int64
			for name, info := range inventory {
				if name != "" {
					candidateBytes += info.Size()
				}
			}
			if candidates >= operatorReleaseCandidateLimit || candidateBytes > operatorReleaseByteLimit-verifiedBytes {
				return nil
			}
			candidates++
			verifiedBytes += candidateBytes
			manifest, err := verifySignedAutomationRelease(path, publicKey, minisignPath)
			if err != nil || manifest.Version != tag {
				return nil
			}
			gate, err = lockReleaseCacheGate(cache)
			if err != nil {
				return err
			}
			defer func() {
				if closeErr := gate.Close(); closeErr != nil {
					retErr = errors.Join(retErr, closeErr)
				}
			}()
			pinRefs, err := operatorReleasePinReferencesLocked(cache)
			if err != nil {
				return err
			}
			if operatorReleasePathReferenced(path, pinRefs) {
				return nil
			}
			// Recheck identity and immutable modes after verification. Never recurse into
			// unknown or linked entries, even when removing a read-only bundle.
			latest, err := operatorReleaseCacheInventory(path)
			if err != nil || !sameReleaseCacheInventory(inventory, latest) || !os.SameFile(lockedInfo, latest[""]) {
				return nil
			}
			if err := os.Chmod(path, 0700); err != nil {
				return err
			}
			for name := range inventory {
				if name == "" {
					continue
				}
				if err := os.Remove(filepath.Join(path, name)); err != nil {
					_ = os.Chmod(path, 0500)
					return err
				}
			}
			if err := os.Remove(path); err != nil {
				_ = os.Chmod(path, 0500)
				return err
			}
			if err := syncUpgradeDirectory(cache); err != nil {
				return err
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func operatorReleasePathReferenced(path string, refs map[string]bool) bool {
	for ref := range refs {
		if ref == path || strings.HasPrefix(ref, path+string(os.PathSeparator)) ||
			strings.HasPrefix(path, strings.TrimSuffix(ref, string(os.PathSeparator))+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// Unknown live metadata cannot prove a cache entry unused: abort before deletion.
func operatorReleaseLiveReferences(root, cache string) (map[string]bool, error) {
	refs := map[string]bool{}
	visited := 0
	var metadataBytes int64
	err := walkOperatorReleaseMetadata(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		visited++
		if visited > operatorReleaseScanLimit {
			return errors.New("operator_release_retention_scan_limit")
		}
		if path == cache {
			return filepath.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("operator_release_retention_metadata_symlink")
		}
		if entry.IsDir() {
			if path != root &&
				(entry.Name() == "bundle" || entry.Name() == "recovery-bundle" || entry.Name() == "ansible-tmp" || entry.Name() == "releases" || entry.Name() == "downloads" || entry.Name() == "__pycache__" || strings.HasPrefix(entry.Name(), "runtime-")) {
				return filepath.SkipDir
			}
			if _, err := os.Lstat(filepath.Join(path, operatorCompletionFile)); err == nil {
				for _, kind := range []string{"upgrade", "bootstrap"} {
					if done, err := completedOperatorOperation(path, kind, ""); done && err == nil {
						return filepath.SkipDir
					}
				}
			}
			return nil
		}
		if entry.Name() != "request.json" && entry.Name() != "runtime-use.json" {
			return nil
		}
		if err := operatorPrivate(path, false); err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil || info.Size() > 4<<20 {
			return errors.New("operator_release_retention_metadata_invalid")
		}
		metadataBytes += info.Size()
		if metadataBytes > 64<<20 {
			return errors.New("operator_release_retention_metadata_limit")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var value any
		if json.Unmarshal(raw, &value) != nil {
			return errors.New("operator_release_retention_metadata_invalid")
		}
		if _, ok := value.(map[string]any); !ok {
			return errors.New("operator_release_retention_metadata_invalid")
		}
		// All absolute strings are conservative references, including future fields.
		collectOperatorPathValues(value, refs)
		return nil
	})
	return refs, err
}

func operatorReleaseCacheInventory(path string) (map[string]os.FileInfo, error) {
	if err := operatorPrivate(path, true); err != nil {
		return nil, err
	}
	root, err := os.Lstat(path)
	if err != nil || root.Mode().Perm() != 0500 {
		return nil, errors.New("operator_release_retention_mutable_directory")
	}
	inventory := map[string]os.FileInfo{"": root}
	directory, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(65)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(entries) > 64 {
		return nil, errors.New("operator_release_retention_inventory_limit")
	}
	var total int64
	for _, entry := range entries {
		info, err := os.Lstat(filepath.Join(path, entry.Name()))
		if err != nil {
			return nil, err
		}
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0400 ||
			info.Size() <= 0 ||
			info.Size() > githubAssetLimit {
			return nil, errors.New("operator_release_retention_unowned_asset")
		}
		total += info.Size()
		if total > githubBundleLimit+4*githubMetadataLimit {
			return nil, errors.New("operator_release_retention_bundle_limit")
		}
		inventory[entry.Name()] = info
	}
	return inventory, nil
}

func sameReleaseCacheInventory(left, right map[string]os.FileInfo) bool {
	if len(left) != len(right) {
		return false
	}
	for name, before := range left {
		after, ok := right[name]
		if !ok || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() ||
			!before.ModTime().Equal(after.ModTime()) {
			return false
		}
	}
	return true
}

// Limit directory reads as well as visited entries; filepath.WalkDir otherwise
// allocates and sorts an entire directory before the visitor can stop it.
func walkOperatorReleaseMetadata(root string, visit fs.WalkDirFunc) error {
	info, err := os.Lstat(root)
	if err != nil {
		return err
	}
	count := 1
	var walk func(string, fs.DirEntry) error
	walk = func(path string, entry fs.DirEntry) error {
		if err := visit(path, entry, nil); err != nil {
			if err == filepath.SkipDir {
				return nil
			}
			return err
		}
		if !entry.IsDir() {
			return nil
		}
		directory, err := os.Open(path)
		if err != nil {
			return err
		}
		remaining := operatorReleaseScanLimit - count
		entries, readErr := directory.ReadDir(remaining + 1)
		closeErr := directory.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if len(entries) > remaining {
			return errors.New("operator_release_retention_scan_limit")
		}
		count += len(entries)
		for _, child := range entries {
			if err := walk(filepath.Join(path, child.Name()), child); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, fs.FileInfoToDirEntry(info))
}
