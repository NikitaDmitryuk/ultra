package config

import (
	"fmt"
	"strconv"
)

const (
	ExitPingIPv4        = "192.0.2.254"
	ExitPingPort        = 80
	ExitPingPath        = "/generate_204"
	ExitPingURL         = "http://192.0.2.254/generate_204"
	exitPingOutboundTag = "exit-ping"
	exitPingBlockTag    = "exit-ping-block"
)

// ValidateExitPing validates only the opt-in dataplane and publication settings.
func (s *Spec) ValidateExitPing() error {
	if len(s.HappProviderID) > 128 {
		return fmt.Errorf("config: happ_provider_id exceeds 128 ASCII characters")
	}
	for _, c := range s.HappProviderID {
		valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
		if !valid {
			return fmt.Errorf("config: happ_provider_id must contain only ASCII letters, digits, hyphens and underscores")
		}
	}
	if s.HappExitPing && (s.Role != RoleBridge || !s.ExitPing || s.HappProviderID == "") {
		return fmt.Errorf("config: happ_exit_ping requires bridge role, exit_ping and happ_provider_id")
	}
	return nil
}

func exitPingRule(tag string) map[string]any {
	return map[string]any{
		"type":        "field",
		"network":     "tcp",
		"ip":          []string{ExitPingIPv4 + "/32"},
		"port":        strconv.Itoa(ExitPingPort),
		"outboundTag": tag,
	}
}

// Reserve the whole address even when disabled, including WARP and direct routes.
func exitPingBlockRule() map[string]any {
	return map[string]any{"type": "field", "ip": []string{ExitPingIPv4 + "/32"}, "outboundTag": exitPingBlockTag}
}

func exitPingBlackhole() map[string]any {
	return map[string]any{"tag": exitPingBlockTag, "protocol": "blackhole", "settings": map[string]any{}}
}
