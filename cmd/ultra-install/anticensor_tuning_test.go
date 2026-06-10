package main

import (
	"encoding/json"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
)

func TestBuildAntiCensorSpecIncludesSplitHTTPTuning(t *testing.T) {
	a := buildAntiCensorSpec(antiCensorTuning{
		DisableDOH:             true,
		DisableFragment:        true,
		SplitHTTPPadding:       "0",
		SplitHTTPMaxChunkKB:    256,
		RealityFingerprintsCSV: "chrome,firefox",
		WARPProxy:              true,
		WARPProxyPort:          40001,
	})
	if !a.DisableDOH {
		t.Fatal("DisableDOH not set")
	}
	if a.Fragment == nil || a.Fragment.Packets != "" {
		t.Fatalf("fragment disable not encoded: %#v", a.Fragment)
	}
	if a.SplitHTTPPadding != "0" {
		t.Fatalf("SplitHTTPPadding = %q, want 0", a.SplitHTTPPadding)
	}
	if a.SplitHTTPMaxChunkKB != 256 {
		t.Fatalf("SplitHTTPMaxChunkKB = %d, want 256", a.SplitHTTPMaxChunkKB)
	}
	if len(a.RealityFingerprints) != 2 || a.RealityFingerprints[0] != "chrome" || a.RealityFingerprints[1] != "firefox" {
		t.Fatalf("RealityFingerprints = %#v", a.RealityFingerprints)
	}
	if !a.WARPProxy || a.WARPProxyPort != 40001 {
		t.Fatalf("WARP settings = %#v", a)
	}
}

func TestNormalizeDomainMatchers(t *testing.T) {
	got := normalizeDomainMatchers([]string{"example.com", "domain:kept.example", "regexp:.*\\.example$"})
	want := []string{"domain:example.com", "domain:kept.example", "regexp:.*\\.example$"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestAppendUniqueStrings(t *testing.T) {
	got := appendUniqueStrings([]string{"domain:a"}, "domain:b", "domain:a", "")
	want := []string{"domain:a", "domain:b"}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBuildExitSpecJSONCarriesSplitHTTPTuning(t *testing.T) {
	exitAnti := buildAntiCensorSpec(antiCensorTuning{
		SplitHTTPPadding:    "0",
		SplitHTTPMaxChunkKB: 128,
		WARPProxy:           true,
		WARPProxyPort:       40000,
	})
	b, err := buildExitSpecJSON(
		"/etc/ultra-relay",
		51001,
		"aaaaaaaa-0000-0000-0000-000000000001",
		"steamlike",
		"client-download.steampowered.com",
		"/depot/123/chunk/abc",
		config.SplitHTTPTLSSpec{ServerName: "client-download.steampowered.com", Alpn: []string{"h2"}, Fingerprint: "chrome"},
		config.TunnelTLSSelfSigned,
		config.TunnelTransportSplitHTTP,
		exitAnti,
	)
	if err != nil {
		t.Fatal(err)
	}
	var spec config.Spec
	if err := json.Unmarshal(b, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.AntiCensor == nil {
		t.Fatal("AntiCensor missing")
	}
	if spec.AntiCensor.SplitHTTPPadding != "0" {
		t.Fatalf("exit SplitHTTPPadding = %q, want 0", spec.AntiCensor.SplitHTTPPadding)
	}
	if spec.AntiCensor.SplitHTTPMaxChunkKB != 128 {
		t.Fatalf("exit SplitHTTPMaxChunkKB = %d, want 128", spec.AntiCensor.SplitHTTPMaxChunkKB)
	}
	if !spec.AntiCensor.WARPProxy {
		t.Fatal("exit WARPProxy not preserved")
	}
}

func TestExitOnlyCopiesBridgeSplitHTTPTuning(t *testing.T) {
	bridge := &config.Spec{
		AntiCensor: &config.AntiCensorSpec{
			SplitHTTPPadding:    "0",
			SplitHTTPMaxChunkKB: 64,
		},
	}
	exitAnti := tunnelSplitHTTPAntiCensorFromBridge(bridge, antiCensorTuning{
		WARPProxy:     true,
		WARPProxyPort: 40000,
	})
	if exitAnti.SplitHTTPPadding != "0" {
		t.Fatalf("exit-only SplitHTTPPadding = %q, want 0", exitAnti.SplitHTTPPadding)
	}
	if exitAnti.SplitHTTPMaxChunkKB != 64 {
		t.Fatalf("exit-only SplitHTTPMaxChunkKB = %d, want 64", exitAnti.SplitHTTPMaxChunkKB)
	}
	if !exitAnti.WARPProxy {
		t.Fatal("exit-only WARPProxy not preserved")
	}
}

func TestExitOnlyTransportValuePreservesBridgeDefault(t *testing.T) {
	if got := exitOnlyTransportValue("splithttp", false); got != "" {
		t.Fatalf("implicit CLI default should not override bridge transport, got %q", got)
	}
	if got := exitOnlyTransportValue("splithttp", true); got != "splithttp" {
		t.Fatalf("explicit transport not preserved: %q", got)
	}
}
