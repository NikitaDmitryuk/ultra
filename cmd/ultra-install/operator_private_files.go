package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

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
