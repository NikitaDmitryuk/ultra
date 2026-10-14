//go:build linux

package main

import (
	"errors"
	"math"
	"syscall"
)

func autoDownloadAvailableBytes(directory string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(directory, &stat); err != nil {
		return 0, err
	}
	if stat.Bsize <= 0 || stat.Bavail > math.MaxUint64/uint64(stat.Bsize) {
		return 0, errors.New("auto_cache_disk_size_invalid")
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}
