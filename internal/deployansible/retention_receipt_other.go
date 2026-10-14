//go:build !linux

package deployansible

import "os"

func retentionSingleLink(_ os.FileInfo) bool { return false }
