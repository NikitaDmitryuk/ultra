package config

import (
	"github.com/NikitaDmitryuk/ultra/mimic"
)

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
	rs := map[string]any{
		"show":        false,
		"dest":        spec.Reality.Dest,
		"xver":        0,
		"serverNames": spec.Reality.ServerNames,
		"privateKey":  spec.Reality.PrivateKey,
		"shortIds":    realityShortIDs(spec.Reality.ShortIDs),
	}
	if spec.Reality.Fingerprint != "" {
		rs["fingerprint"] = spec.Reality.Fingerprint
	} else {
		rs["fingerprint"] = "chrome"
	}
	spx := spec.Reality.SpiderX
	if spx == "" {
		spx = "/"
	}
	rs["spiderX"] = spx
	inStream["realitySettings"] = rs
	return inStream
}

func splithttpOutboundStream(spec *Spec, strat mimic.Strategy) map[string]any {
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
	return map[string]any{
		"network":     "splithttp",
		"security":    "tls",
		"tlsSettings": tlsSettings,
		"splithttpSettings": map[string]any{
			"host":    host,
			"path":    path,
			"mode":    "packet-up",
			"headers": headers,
		},
	}
}

func splithttpInboundStream(spec *Spec, strat mimic.Strategy) map[string]any {
	tlsSN, alpn, tlsFP := resolveSplithttpTLS(spec, strat)
	path := resolveSplithttpPath(spec, strat)
	headers := strat.ExtraHeaders()
	host := splithttpHTTPHost(spec, strat)
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
		"splithttpSettings": map[string]any{
			"host":    host,
			"path":    path,
			"mode":    "packet-up",
			"headers": headers,
		},
	}
}
