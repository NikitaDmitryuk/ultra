package config

// XrayWireSpec overrides names and constants embedded in generated Xray JSON.
// Omitted fields use defaults from resolveXrayWire (see deploy/spec.bridge.example.json).
type XrayWireSpec struct {
	InboundVLESSTag      string   `json:"inbound_vless_tag,omitempty"`
	InboundSocksTag      string   `json:"inbound_socks_tag,omitempty"`
	ExitInboundTunnelTag string   `json:"exit_inbound_tunnel_tag,omitempty"`
	ExitTunnelUserLabel  string   `json:"exit_tunnel_user_label,omitempty"`
	OutboundExitTag      string   `json:"outbound_exit_tag,omitempty"`
	OutboundDirectTag    string   `json:"outbound_direct_tag,omitempty"`
	VLESSEncryption      string   `json:"vless_encryption,omitempty"`
	SniffingDestOverride []string `json:"sniffing_dest_override,omitempty"`
	DomainMatcherSplit   string   `json:"domain_matcher_split,omitempty"`
	SplithttpMode        string   `json:"splithttp_mode,omitempty"`
	RuDirectGeoipMatcher string   `json:"ru_direct_geoip_matcher,omitempty"`

	ClientOutboundTag     string `json:"client_outbound_tag,omitempty"`
	ClientSOCKSInboundTag string `json:"client_local_socks_inbound_tag,omitempty"`
	ClientSOCKSListen     string `json:"client_local_socks_listen,omitempty"`
	ClientSOCKSPort       int    `json:"client_local_socks_port,omitempty"`
	ClientFullLogLevel    string `json:"client_full_config_loglevel,omitempty"`

	// SocksAuth is Xray socks inbound auth mode (typically "password").
	SocksAuth string `json:"socks_auth,omitempty"`
}

type xrayWireResolved struct {
	InboundVLESSTag      string
	InboundSocksTag      string
	ExitInboundTunnelTag string
	ExitTunnelUserLabel  string
	OutboundExitTag      string
	OutboundDirectTag    string
	VLESSEncryption      string
	SniffingDestOverride []string
	DomainMatcherSplit   string
	SplithttpMode        string
	RuDirectGeoipMatcher string

	ClientOutboundTag     string
	ClientSOCKSInboundTag string
	ClientSOCKSListen     string
	ClientSOCKSPort       int
	ClientFullLogLevel    string
	SocksAuth             string
}

func resolveXrayWire(s *Spec) xrayWireResolved {
	r := xrayWireResolved{
		InboundVLESSTag:      "vless-in",
		InboundSocksTag:      "socks-in",
		ExitInboundTunnelTag: "vless-splithttp",
		ExitTunnelUserLabel:  "tunnel",
		OutboundExitTag:      "to-exit",
		OutboundDirectTag:    "direct",
		VLESSEncryption:      "none",
		SniffingDestOverride: []string{"http", "tls", "quic"},
		DomainMatcherSplit:   "mph",
		SplithttpMode:        "packet-up",
		RuDirectGeoipMatcher: "geoip:ru",

		ClientOutboundTag:     "proxy",
		ClientSOCKSInboundTag: "socks-in",
		ClientSOCKSListen:     "127.0.0.1",
		ClientSOCKSPort:       10808,
		ClientFullLogLevel:    "warning",
		SocksAuth:             "password",
	}
	if s == nil || s.XrayWire == nil {
		return r
	}
	w := s.XrayWire
	if w.InboundVLESSTag != "" {
		r.InboundVLESSTag = w.InboundVLESSTag
	}
	if w.InboundSocksTag != "" {
		r.InboundSocksTag = w.InboundSocksTag
	}
	if w.ExitInboundTunnelTag != "" {
		r.ExitInboundTunnelTag = w.ExitInboundTunnelTag
	}
	if w.ExitTunnelUserLabel != "" {
		r.ExitTunnelUserLabel = w.ExitTunnelUserLabel
	}
	if w.OutboundExitTag != "" {
		r.OutboundExitTag = w.OutboundExitTag
	}
	if w.OutboundDirectTag != "" {
		r.OutboundDirectTag = w.OutboundDirectTag
	}
	if w.VLESSEncryption != "" {
		r.VLESSEncryption = w.VLESSEncryption
	}
	if len(w.SniffingDestOverride) > 0 {
		r.SniffingDestOverride = append([]string(nil), w.SniffingDestOverride...)
	}
	if w.DomainMatcherSplit != "" {
		r.DomainMatcherSplit = w.DomainMatcherSplit
	}
	if w.SplithttpMode != "" {
		r.SplithttpMode = w.SplithttpMode
	}
	if w.RuDirectGeoipMatcher != "" {
		r.RuDirectGeoipMatcher = w.RuDirectGeoipMatcher
	}
	if w.ClientOutboundTag != "" {
		r.ClientOutboundTag = w.ClientOutboundTag
	}
	if w.ClientSOCKSInboundTag != "" {
		r.ClientSOCKSInboundTag = w.ClientSOCKSInboundTag
	}
	if w.ClientSOCKSListen != "" {
		r.ClientSOCKSListen = w.ClientSOCKSListen
	}
	if w.ClientSOCKSPort > 0 {
		r.ClientSOCKSPort = w.ClientSOCKSPort
	}
	if w.ClientFullLogLevel != "" {
		r.ClientFullLogLevel = w.ClientFullLogLevel
	}
	if w.SocksAuth != "" {
		r.SocksAuth = w.SocksAuth
	}
	return r
}
