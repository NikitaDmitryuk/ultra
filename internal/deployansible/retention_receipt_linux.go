//go:build linux

package deployansible

import (
	"os"
	"syscall"
)

func retentionSingleLink(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Nlink == 1
}
