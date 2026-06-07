package config

import "testing"

func TestPublicVLESSFlow(t *testing.T) {
	if got := (&Spec{DevMode: true}).PublicVLESSFlow(); got != "" {
		t.Fatalf("dev_mode: got %q", got)
	}
	if got := (&Spec{VLESSFlow: "none"}).PublicVLESSFlow(); got != "" {
		t.Fatalf("none: got %q", got)
	}
	if got := (&Spec{}).PublicVLESSFlow(); got != DefaultVLESSFlow {
		t.Fatalf("default: got %q want %q", got, DefaultVLESSFlow)
	}
	if got := (&Spec{VLESSFlow: "custom-flow"}).PublicVLESSFlow(); got != "custom-flow" {
		t.Fatalf("custom: got %q", got)
	}
}
