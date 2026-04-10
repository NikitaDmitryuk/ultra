package config

import (
	"math/rand"
	"net"
	"strconv"

	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

// defaultRealityFingerprints is the fingerprint pool used when no list is configured.
// Rotating among realistic browser fingerprints makes REALITY traffic harder to fingerprint.
var defaultRealityFingerprints = []string{
	"chrome", "firefox", "safari", "ios", "android", "randomized",
}

// pickFingerprint returns a random fingerprint from the configured list (or the default pool).
func pickFingerprint(spec *Spec) string {
	pool := defaultRealityFingerprints
	if spec.AntiCensor != nil && len(spec.AntiCensor.RealityFingerprints) > 0 {
		pool = spec.AntiCensor.RealityFingerprints
	}
	return pool[rand.Intn(len(pool))]
}

// buildFragmentSockopt returns a sockopt map with fragment settings for the bridge→exit outbound,
// or nil if fragmentation is disabled.
func buildFragmentSockopt(spec *Spec) map[string]any {
	if spec.AntiCensor == nil {
		// Feature on by default with sensible params.
		return map[string]any{
			"fragment": map[string]any{
				"packets":  "tlshello",
				"length":   "100-200",
				"interval": "10-20",
			},
		}
	}
	f := spec.AntiCensor.Fragment
	if f == nil {
		// AntiCensor present but fragment not set — keep default on.
		return map[string]any{
			"fragment": map[string]any{
				"packets":  "tlshello",
				"length":   "100-200",
				"interval": "10-20",
			},
		}
	}
	if f.Packets == "" {
		// Explicit empty packets = disabled.
		return nil
	}
	length := f.Length
	if length == "" {
		length = "100-200"
	}
	interval := f.Interval
	if interval == "" {
		interval = "10-20"
	}
	return map[string]any{
		"fragment": map[string]any{
			"packets":  f.Packets,
			"length":   length,
			"interval": interval,
		},
	}
}

// splithttpExtraSettings returns optional splithttp performance/obfuscation overrides.
// Default padding "100-1000" obscures chunk sizes; set SplitHTTPPadding="0" to disable.
func splithttpExtraSettings(spec *Spec) map[string]any {
	extra := map[string]any{}

	// Padding is on by default; spec may override or disable with "0".
	padding := "100-1000"
	if spec.AntiCensor != nil && spec.AntiCensor.SplitHTTPPadding != "" {
		padding = spec.AntiCensor.SplitHTTPPadding
	}
	if padding != "0" {
		extra["xPaddingSize"] = padding
	}

	if spec.AntiCensor != nil && spec.AntiCensor.SplitHTTPMaxChunkKB > 0 {
		extra["scMaxEachPostBytes"] = spec.AntiCensor.SplitHTTPMaxChunkKB * 1024
	}
	return extra
}

// splitHostPort splits "host:port" into its components.
// Returns ("127.0.0.1", 10085, nil) on any parse error as a safe fallback.
func splitHostPort(addr string) (host string, port int, err error) {
	h, p, e := net.SplitHostPort(addr)
	if e != nil {
		return "127.0.0.1", 10085, e
	}
	n, e := strconv.Atoi(p)
	if e != nil {
		return "127.0.0.1", 10085, e
	}
	return h, n, nil
}

func realityShortIDs(ids []string) []string {
	if len(ids) == 0 {
		return []string{""}
	}
	return ids
}

func resolveSplithttpPath(spec *Spec, strat mimic.Strategy) string {
	path := spec.SplithttpPath
	if path == "" {
		path = strat.NextPath()
	}
	return path
}

func splithttpHTTPHost(spec *Spec, strat mimic.Strategy) string {
	if spec.SplithttpHost != "" {
		return spec.SplithttpHost
	}
	return strat.Host()
}

func resolveSplithttpTLS(spec *Spec, strat mimic.Strategy) (serverName string, alpn []string, fingerprint string) {
	tlsSN := spec.SplitHTTPTLS.ServerName
	if tlsSN == "" {
		tlsSN = strat.Host()
	}
	alpn = spec.SplitHTTPTLS.Alpn
	if len(alpn) == 0 {
		alpn = []string{"h2"}
	}
	tlsFP := spec.SplitHTTPTLS.Fingerprint
	if tlsFP == "" {
		tlsFP = "chrome"
	}
	return tlsSN, alpn, tlsFP
}

func bridgeInboundStream(spec *Spec) map[string]any {
	inStream := map[string]any{}
	if spec.DevMode {
		inStream["network"] = "tcp"
		inStream["security"] = "none"
		return inStream
	}
	inStream["network"] = "tcp"
	inStream["security"] = "reality"
	// Prefer single configured fingerprint; fall back to random rotation from the pool.
	fp := spec.Reality.Fingerprint
	if fp == "" {
		fp = pickFingerprint(spec)
	}
	rs := map[string]any{
		"show":        false,
		"dest":        spec.Reality.Dest,
		"xver":        0,
		"serverNames": spec.Reality.ServerNames,
		"privateKey":  spec.Reality.PrivateKey,
		"shortIds":    realityShortIDs(spec.Reality.ShortIDs),
		"fingerprint": fp,
	}
	spx := spec.Reality.SpiderX
	if spx == "" {
		spx = "/"
	}
	rs["spiderX"] = spx
	inStream["realitySettings"] = rs
	return inStream
}

func splithttpOutboundStream(spec *Spec, strat mimic.Strategy, w xrayWireResolved) map[string]any {
	tlsSN, alpn, tlsFP := resolveSplithttpTLS(spec, strat)
	path := resolveSplithttpPath(spec, strat)
	headers := strat.ExtraHeaders()
	host := splithttpHTTPHost(spec, strat)
	tlsSettings := map[string]any{
		"serverName":  tlsSN,
		"alpn":        alpn,
		"fingerprint": tlsFP,
	}
	// Self-signed on exit is not in the public trust store; bridge client must skip CA verify (see deploy/TLS.md).
	if spec.TunnelTLSProvision == TunnelTLSSelfSigned {
		tlsSettings["allowInsecure"] = true
	}

	splithttpCfg := map[string]any{
		"host":    host,
		"path":    path,
		"mode":    w.SplithttpMode,
		"headers": headers,
	}
	for k, v := range splithttpExtraSettings(spec) {
		splithttpCfg[k] = v
	}

	out := map[string]any{
		"network":           "splithttp",
		"security":          "tls",
		"tlsSettings":       tlsSettings,
		"splithttpSettings": splithttpCfg,
	}

	// TLS ClientHello fragmentation: prevents DPI from reading the SNI of the bridge→exit tunnel.
	if sockopt := buildFragmentSockopt(spec); len(sockopt) > 0 {
		out["sockopt"] = sockopt
	}

	return out
}

func splithttpInboundStream(spec *Spec, strat mimic.Strategy, w xrayWireResolved) map[string]any {
	tlsSN, alpn, tlsFP := resolveSplithttpTLS(spec, strat)
	path := resolveSplithttpPath(spec, strat)
	headers := strat.ExtraHeaders()
	host := splithttpHTTPHost(spec, strat)

	splithttpCfg := map[string]any{
		"host":    host,
		"path":    path,
		"mode":    w.SplithttpMode,
		"headers": headers,
	}
	for k, v := range splithttpExtraSettings(spec) {
		splithttpCfg[k] = v
	}

	return map[string]any{
		"network":  "splithttp",
		"security": "tls",
		"tlsSettings": map[string]any{
			"alpn": alpn,
			"certificates": []any{
				map[string]any{
					"certificateFile": spec.ExitCertPaths.CertFile,
					"keyFile":         spec.ExitCertPaths.KeyFile,
				},
			},
			"serverName":  tlsSN,
			"fingerprint": tlsFP,
		},
		"splithttpSettings": splithttpCfg,
	}
}
