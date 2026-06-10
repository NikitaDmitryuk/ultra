package main

import (
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/config"
)

type antiCensorTuning struct {
	DisableDOH             bool
	DisableFragment        bool
	SplitHTTPPadding       string
	SplitHTTPMaxChunkKB    int
	RealityFingerprintsCSV string
	WARPProxy              bool
	WARPProxyPort          int
}

func buildAntiCensorSpec(t antiCensorTuning) *config.AntiCensorSpec {
	a := &config.AntiCensorSpec{}
	if t.DisableDOH {
		a.DisableDOH = true
	}
	if t.DisableFragment {
		a.Fragment = &config.FragmentSpec{}
	}
	if p := strings.TrimSpace(t.SplitHTTPPadding); p != "" {
		a.SplitHTTPPadding = p
	}
	if t.SplitHTTPMaxChunkKB > 0 {
		a.SplitHTTPMaxChunkKB = t.SplitHTTPMaxChunkKB
	}
	if fps := splitCommaNonEmpty(t.RealityFingerprintsCSV); len(fps) > 0 {
		a.RealityFingerprints = fps
	}
	if t.WARPProxy {
		a.WARPProxy = true
		a.WARPProxyPort = t.WARPProxyPort
	}
	return a
}

func tunnelSplitHTTPAntiCensorFromBridge(bridge *config.Spec, t antiCensorTuning) *config.AntiCensorSpec {
	if bridge != nil && bridge.AntiCensor != nil {
		if t.SplitHTTPPadding == "" {
			t.SplitHTTPPadding = bridge.AntiCensor.SplitHTTPPadding
		}
		if t.SplitHTTPMaxChunkKB <= 0 {
			t.SplitHTTPMaxChunkKB = bridge.AntiCensor.SplitHTTPMaxChunkKB
		}
	}
	return buildAntiCensorSpec(t)
}
