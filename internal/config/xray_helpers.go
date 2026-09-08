package config

import (
	"net"
	"strconv"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

// buildFragmentSockopt chains the opt-in freedom fragment outbound.
func buildFragmentSockopt(spec *Spec) map[string]any {
	if spec.AntiCensor == nil || spec.AntiCensor.Fragment == nil || spec.AntiCensor.Fragment.Packets == "" {
		return nil
	}
	return map[string]any{"dialerProxy": "fragment-tunnel"}
}

func tunnelFragmentOutbound(spec *Spec) map[string]any {
	if buildFragmentSockopt(spec) == nil {
		return nil
	}
	f := *spec.AntiCensor.Fragment
	if f.Length == "" {
		f.Length = "100-200"
	}
	if f.Interval == "" {
		f.Interval = "1-3"
	}
	return map[string]any{"tag": "fragment-tunnel", "protocol": "freedom", "settings": map[string]any{"fragment": f}}
}

func splithttpExtraSettings(spec *Spec) map[string]any {
	extra := map[string]any{"xPaddingBytes": effectivePadding(spec)}
	if spec.AntiCensor != nil && spec.AntiCensor.SplitHTTPMaxChunkKB > 0 && resolveXrayWire(spec).SplithttpMode == "packet-up" {
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
		// Stable across rebuilds and both peers when an explicit path is absent.
		path = "/xhttp"
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
	if spec.SplitHTTPTLS.OmitSNI {
		tlsSN = ""
	} else if tlsSN == "" {
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
	// This server field does not control or rotate the client ClientHello.
	fp := clientRealityFingerprint(spec)
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

func splithttpOutboundStream(spec *Spec, strat mimic.Strategy, w xrayWireResolved, pinnedPeerCertSHA256 string) map[string]any {
	tlsSN, alpn, tlsFP := resolveSplithttpTLS(spec, strat)
	path := resolveSplithttpPath(spec, strat)
	headers := strat.ExtraHeaders()
	host := splithttpHTTPHost(spec, strat)
	tlsSettings := map[string]any{
		"serverName":  tlsSN,
		"alpn":        alpn,
		"fingerprint": tlsFP,
	}
	applySelfSignedTunnelTLSClient(tlsSettings, spec.TunnelTLSProvision, pinnedPeerCertSHA256)

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

	// TLS ClientHello fragmentation: obfuscates the SNI of the bridge→exit tunnel.
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
					"oneTimeLoading":  true,
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

const defaultGRPCInitialWindowSize = 4 * 1024 * 1024 // 4 MiB — eliminates flow-control stalls at 47 ms RTT

// grpcInitialWindowSize returns the HTTP/2 per-stream window size for the gRPC tunnel.
// The default 32 KiB Xray value causes repeated WINDOW_UPDATE round-trips on high-latency
// links, inflating upload latency under load. 4 MiB keeps the window large enough that
// stalls never occur at practical throughput rates.
func grpcInitialWindowSize(spec *Spec) int {
	if spec.AntiCensor != nil && spec.AntiCensor.GRPCInitialWindowSize > 0 {
		return spec.AntiCensor.GRPCInitialWindowSize
	}
	return defaultGRPCInitialWindowSize
}

// grpcServiceName derives a gRPC serviceName from the spec.
// Reuses SplithttpPath (stripped of leading "/") so bridge and exit agree on the same identifier.
func grpcServiceName(spec *Spec) string {
	p := strings.TrimPrefix(spec.SplithttpPath, "/")
	if p != "" {
		return p
	}
	return "relay.v1.Tunnel"
}

// grpcOutboundStream builds the bridge→exit outbound stream settings using gRPC transport.
func grpcOutboundStream(spec *Spec, strat mimic.Strategy, pinnedPeerCertSHA256 string) map[string]any {
	tlsSN, alpn, tlsFP := resolveSplithttpTLS(spec, strat)
	tlsSettings := map[string]any{
		"serverName":  tlsSN,
		"alpn":        alpn,
		"fingerprint": tlsFP,
	}
	applySelfSignedTunnelTLSClient(tlsSettings, spec.TunnelTLSProvision, pinnedPeerCertSHA256)
	out := map[string]any{
		"network":     "grpc",
		"security":    "tls",
		"tlsSettings": tlsSettings,
		"grpcSettings": map[string]any{
			"serviceName":        grpcServiceName(spec),
			"multiMode":          true,
			"initialWindowsSize": grpcInitialWindowSize(spec),
		},
	}
	if sockopt := buildFragmentSockopt(spec); len(sockopt) > 0 {
		out["sockopt"] = sockopt
	}
	return out
}

// grpcInboundStream builds the exit node inbound stream settings using gRPC transport.
func grpcInboundStream(spec *Spec, strat mimic.Strategy) map[string]any {
	tlsSN, alpn, tlsFP := resolveSplithttpTLS(spec, strat)
	return map[string]any{
		"network":  "grpc",
		"security": "tls",
		"tlsSettings": map[string]any{
			"alpn": alpn,
			"certificates": []any{
				map[string]any{
					"oneTimeLoading":  true,
					"certificateFile": spec.ExitCertPaths.CertFile,
					"keyFile":         spec.ExitCertPaths.KeyFile,
				},
			},
			"serverName":  tlsSN,
			"fingerprint": tlsFP,
		},
		"grpcSettings": map[string]any{
			"serviceName":        grpcServiceName(spec),
			"multiMode":          true,
			"initialWindowsSize": grpcInitialWindowSize(spec),
		},
	}
}
