package loglevel

import (
	"log/slog"
	"testing"
)

func TestParseRelayLogLevel(t *testing.T) {
	tests := []struct {
		in       string
		wantSlog slog.Level
		wantXray string
	}{
		{"debug", slog.LevelDebug, "debug"},
		{"INFO", slog.LevelInfo, "info"},
		{"warn", slog.LevelWarn, "warning"},
		{"warning", slog.LevelWarn, "warning"},
		{"error", slog.LevelError, "error"},
		{"none", slog.LevelInfo, "none"},
		{"", slog.LevelInfo, "warning"},
	}
	for _, tt := range tests {
		sl, xr, err := ParseRelayLogLevel(tt.in)
		if err != nil {
			t.Fatalf("%q: %v", tt.in, err)
		}
		if sl != tt.wantSlog || xr != tt.wantXray {
			t.Fatalf("%q: got slog=%v xray=%q want slog=%v xray=%q", tt.in, sl, xr, tt.wantSlog, tt.wantXray)
		}
	}
	if _, _, err := ParseRelayLogLevel("bogus"); err == nil {
		t.Fatal("expected error")
	}
}
