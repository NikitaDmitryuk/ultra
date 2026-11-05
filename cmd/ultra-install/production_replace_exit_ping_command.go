package main

import (
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func runReplacementPingProbeCommand(args []string) error {
	return withReplacementPingReceipt(func(output io.Writer) error {
		return runReplacementPingProbe(args, output)
	})
}

// Only the dedicated hidden command may redirect the process's stdout. Xray
// configuration can log before its requested log level takes effect, and its
// asynchronous logger can outlive the probe. Keep fd 1 redirected permanently;
// only the reserved, close-on-exec descriptor carries the strict JSON receipt.
func withReplacementPingReceipt(probe func(io.Writer) error) (result error) {
	fail := errors.New("replacement_exit_ping_receipt_channel_failed")
	fd, err := unix.FcntlInt(os.Stdout.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return fail
	}
	receipt := os.NewFile(uintptr(fd), "exit-ping-receipt")
	defer func() {
		if err := receipt.Close(); err != nil && result == nil {
			result = fail
		}
	}()
	if err := unix.Dup2(int(os.Stderr.Fd()), int(os.Stdout.Fd())); err != nil {
		return fail
	}
	return probe(receipt)
}
