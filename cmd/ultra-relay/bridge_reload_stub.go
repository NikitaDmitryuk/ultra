//go:build !unix

package main

import (
	"log/slog"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
)

func registerSplitRoutingUSR1(_ *slog.Logger, _ func([]auth.User), _ auth.UserManager) {
	// ultra-relay is intended for Linux servers; non-Unix builds omit SIGUSR1 reload.
}
