package installplan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"
)

// DatabaseDumpDigest binds a private custom archive without reading its contents into logs.
func DatabaseDumpDigest(path string) (string, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 || before.Size() < 5 || before.Size() > 8<<30 {
		return "", fmt.Errorf("DATABASE_DUMP must be a private regular custom archive (at most 8 GiB)")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("DATABASE_DUMP unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) {
		return "", fmt.Errorf("DATABASE_DUMP changed")
	}
	header := make([]byte, 5)
	if _, err = io.ReadFull(f, header); err != nil || string(header) != "PGDMP" {
		return "", fmt.Errorf("DATABASE_DUMP requires custom pg_dump format")
	}
	h := sha256.New()
	h.Write(header)
	if _, err = io.Copy(h, f); err != nil {
		return "", fmt.Errorf("DATABASE_DUMP read failed")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyDatabaseDump validates the archive locally before dispatching any mutator.
func VerifyDatabaseDump(path, expected string) error {
	sum, err := DatabaseDumpDigest(path)
	if err != nil {
		return err
	}
	if sum != expected {
		return fmt.Errorf("DATABASE_DUMP changed after planning")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "pg_restore", "--list", path)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("DATABASE_DUMP validation requires working local pg_restore and a valid archive")
	}
	return nil
}
