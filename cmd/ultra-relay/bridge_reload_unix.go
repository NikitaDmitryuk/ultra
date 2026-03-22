//go:build unix

package main

import (
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
)

func registerSplitRoutingUSR1(log *slog.Logger, reload func([]auth.User), mgr *auth.Manager) {
	sigReload := make(chan os.Signal, 1)
	signal.Notify(sigReload, syscall.SIGUSR1)
	go func() {
		for range sigReload {
			log.Info("received SIGUSR1, reloading xray config")
			reload(mgr.List())
		}
	}()
}
