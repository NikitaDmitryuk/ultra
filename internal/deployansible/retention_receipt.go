package deployansible

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

// WriteRetentionReceipt records a freshly prepared immutable tree. publishedRoot
// may differ from root while preparing an atomic job-directory publication.
// The caller must own the tree exclusively until execution starts.
func WriteRetentionReceipt(root, publishedRoot, receiptPath string, identity any) error {
	if !filepath.IsAbs(root) || !filepath.IsAbs(publishedRoot) || !filepath.IsAbs(receiptPath) ||
		filepath.Clean(publishedRoot) != publishedRoot {
		return errors.New("retention paths invalid")
	}
	for _, path := range []string{root, publishedRoot, filepath.Dir(receiptPath)} {
		if err := retentionNoSymlinkAncestors(path); err != nil {
			return err
		}
	}
	inventory, err := retentionInventory(root)
	if err != nil {
		return err
	}
	receipt := struct {
		Schema    int            `json:"schema"`
		Path      string         `json:"path"`
		Identity  any            `json:"identity"`
		Inventory map[string]any `json:"inventory"`
	}{1, publishedRoot, identity, inventory}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	parent := filepath.Dir(receiptPath)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
		return errors.New("private retention receipt directory required")
	}
	// Hard-link publication is create-only and atomic: an interrupted writer can
	// never leave a truncated authoritative receipt or overwrite an older owner.
	temporary, err := os.CreateTemp(parent, ".retention-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(temporary.Name()) }()
	if _, err = temporary.Write(raw); err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Link(temporary.Name(), receiptPath); os.IsExist(err) {
		// A crash after link publication can leave a second link at the writer's
		// private temporary name. Metadata is accepted only when its complete bytes
		// match; do not unlink aliases whose provenance cannot be established. The
		// source inventory still requires single-link regular executable files.
		info, statErr := os.Lstat(receiptPath)
		if statErr != nil || !info.Mode().IsRegular() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
			return errors.New("retention receipt invalid")
		}
		existing, readErr := os.ReadFile(receiptPath)
		if readErr != nil || !bytes.Equal(existing, raw) {
			return errors.New("retention receipt conflict")
		}
	} else if err != nil {
		return err
	}
	if err = os.Remove(temporary.Name()); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func retentionInventory(root string) (map[string]any, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || !ownedByProcess(rootInfo) || rootInfo.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private retention tree required")
	}
	inventory := map[string]any{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !ownedByProcess(info) || info.Mode().Perm()&0022 != 0 ||
			info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return errors.New("retention tree ownership invalid")
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			if err = syncDirectory(path); err != nil {
				return err
			}
			if relative != "." {
				inventory[filepath.ToSlash(relative)] = []any{"directory", uint32(info.Mode().Perm())}
			}
			return nil
		}
		if !info.Mode().IsRegular() || !retentionSingleLink(info) {
			return errors.New("retention tree file invalid")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close() //nolint:errcheck
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) {
			return errors.New("retention tree changed")
		}
		digest := sha256.New()
		if _, err = io.Copy(digest, file); err != nil {
			return err
		}
		if err = file.Sync(); err != nil {
			return err
		}
		inventory[filepath.ToSlash(relative)] = []any{"file", hex.EncodeToString(digest.Sum(nil)), uint32(info.Mode().Perm())}
		return nil
	})
	return inventory, err
}

func retentionNoSymlinkAncestors(path string) error {
	for path != "." {
		info, err := os.Lstat(path)
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("retention path symlink")
		}
		parent := filepath.Dir(path)
		if parent == path {
			break
		}
		path = parent
	}
	return nil
}
