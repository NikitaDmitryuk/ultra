package installplan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// DatabaseTunnelPrivateKeyDigest pins an operator-local key without serializing
// its contents. Key format and lack of passphrase are checked on bridge by ssh-keygen.
func DatabaseTunnelPrivateKeyDigest(path string) (string, error) {
	invalid := errors.New("DB_TUNNEL_PRIVATE_KEY_FILE requires an absolute clean path to a nonempty regular file with mode 0400 or 0600 (at most 64 KiB)")
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", invalid
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || (before.Mode() != 0400 && before.Mode() != 0600) || before.Size() < 1 || before.Size() > 64<<10 {
		return "", invalid
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", invalid
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) || info.Mode() != before.Mode() || info.Size() != before.Size() {
		return "", invalid
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.LimitReader(f, (64<<10)+1)); err != nil {
		return "", invalid
	}
	after, err := f.Stat()
	if err != nil || after.Size() != info.Size() || after.ModTime() != info.ModTime() || after.Mode() != info.Mode() {
		return "", invalid
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyDatabaseTunnelPrivateKey refuses a replaced or changed bootstrap input.
func VerifyDatabaseTunnelPrivateKey(path, expected string) error {
	sum, err := DatabaseTunnelPrivateKeyDigest(path)
	if err != nil {
		return err
	}
	if expected == "" || sum != expected {
		return errors.New("DB_TUNNEL_PRIVATE_KEY_FILE changed after planning")
	}
	return nil
}
