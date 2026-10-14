//go:build !linux

package main

import "errors"

func autoDownloadAvailableBytes(_ string) (uint64, error) {
	return 0, errors.New("auto_controller_architecture_unsupported")
}
