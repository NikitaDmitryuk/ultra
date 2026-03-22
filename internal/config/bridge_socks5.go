package config

// BridgeSOCKS5Spec enables a password-authenticated SOCKS5 inbound on the bridge.
// Traffic uses the same routing rules as VLESS (split to exit or direct).
type BridgeSOCKS5Spec struct {
	Enabled bool `json:"enabled"`
	// ListenAddress binds SOCKS. If empty, defaults to 127.0.0.1 (not spec.listen_address)
	// so SOCKS is not exposed on the WAN when the public inbound uses 0.0.0.0.
	// Set explicitly (e.g. 0.0.0.0) to listen on all interfaces.
	ListenAddress string `json:"listen_address,omitempty"`
	Port          int    `json:"port"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	// UDP nil or true enables UDP associate (default true). Explicit false disables.
	UDP *bool `json:"udp,omitempty"`
}

func (s *Spec) bridgeSOCKS5() *BridgeSOCKS5Spec {
	if s == nil || s.SOCKS5 == nil || !s.SOCKS5.Enabled {
		return nil
	}
	return s.SOCKS5
}

func socks5UDPEnabled(s *BridgeSOCKS5Spec) bool {
	if s == nil {
		return false
	}
	if s.UDP == nil {
		return true
	}
	return *s.UDP
}

const socks5DefaultListenAddress = "127.0.0.1"

func socks5ListenAddress(_ *Spec, s *BridgeSOCKS5Spec) string {
	if s.ListenAddress != "" {
		return s.ListenAddress
	}
	return socks5DefaultListenAddress
}
