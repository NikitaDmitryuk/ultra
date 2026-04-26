package bot

import (
	"testing"
	"time"
)

func TestParseWindow(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    time.Duration
		wantErr bool
	}{
		{name: "default", in: "", want: 24 * time.Hour},
		{name: "1h", in: "1h", want: time.Hour},
		{name: "24h", in: "24h", want: 24 * time.Hour},
		{name: "7d", in: "7d", want: 7 * 24 * time.Hour},
		{name: "30d", in: "30d", want: 30 * 24 * time.Hour},
		{name: "invalid", in: "2d", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseWindow(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("duration mismatch: got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDefaultBucketForWindow(t *testing.T) {
	tests := []struct {
		window time.Duration
		want   string
	}{
		{window: time.Hour, want: "5m"},
		{window: 24 * time.Hour, want: "5m"},
		{window: 48 * time.Hour, want: "1h"},
		{window: 7 * 24 * time.Hour, want: "1h"},
		{window: 10 * 24 * time.Hour, want: "6h"},
		{window: 30 * 24 * time.Hour, want: "6h"},
		{window: 90 * 24 * time.Hour, want: "1d"},
	}
	for _, tc := range tests {
		got := defaultBucketForWindow(tc.window)
		if got != tc.want {
			t.Fatalf("bucket mismatch for %v: got %q, want %q", tc.window, got, tc.want)
		}
	}
}
