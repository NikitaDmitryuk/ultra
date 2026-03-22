// Package loglevel maps a single user-facing level string to slog and Xray log levels.
package loglevel

import (
	"fmt"
	"log/slog"
	"strings"
)

// ParseRelayLogLevel converts a level name into slog.Level and an Xray "loglevel" string.
// Recognized: debug, info, warning (or warn), error, none.
// For xray "none", slog stays at info so ultra-relay messages still appear.
func ParseRelayLogLevel(s string) (slog.Level, string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return slog.LevelInfo, "warning", nil
	}
	switch s {
	case "debug":
		return slog.LevelDebug, "debug", nil
	case "info":
		return slog.LevelInfo, "info", nil
	case "warn", "warning":
		return slog.LevelWarn, "warning", nil
	case "error":
		return slog.LevelError, "error", nil
	case "none":
		return slog.LevelInfo, "none", nil
	default:
		return 0, "", fmt.Errorf("loglevel: unknown level %q (want debug, info, warning, error, none)", s)
	}
}
