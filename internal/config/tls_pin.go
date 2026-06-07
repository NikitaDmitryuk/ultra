package config

import "strings"

// normalizeCertSHA256 returns lowercase hex SHA-256 without colons (Xray pinnedPeerCertSha256 format).
func normalizeCertSHA256(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, ":", "")
	return strings.ToLower(s)
}

// applySelfSignedTunnelTLSClient configures bridge→exit TLS client settings for self-signed exit certs.
// Xray 26+ rejects allowInsecure; pinnedPeerCertSha256 pins the exit leaf certificate instead.
func applySelfSignedTunnelTLSClient(tlsSettings map[string]any, provision TunnelTLSProvision, pinnedSHA256 string) {
	if provision != TunnelTLSSelfSigned {
		return
	}
	if pin := normalizeCertSHA256(pinnedSHA256); pin != "" {
		tlsSettings["pinnedPeerCertSha256"] = pin
	}
}
