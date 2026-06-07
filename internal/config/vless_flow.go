package config

import "strings"

// DefaultVLESSFlow is the Xray flow for public REALITY clients (Xray 26+ recommendation).
const DefaultVLESSFlow = "xtls-rprx-vision"

// vlessFlowDisabled marks an explicit opt-out from default flow in spec JSON / install flags.
const vlessFlowDisabled = "none"

// PublicVLESSFlow returns the VLESS flow for bridge public inbound and client export.
// Empty when dev_mode or flow explicitly disabled (vless_flow: "none").
func (s *Spec) PublicVLESSFlow() string {
	if s == nil || s.DevMode {
		return ""
	}
	f := strings.TrimSpace(s.VLESSFlow)
	if f == vlessFlowDisabled {
		return ""
	}
	if f != "" {
		return f
	}
	return DefaultVLESSFlow
}
