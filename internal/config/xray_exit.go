package config

import (
	"encoding/json"
	"fmt"

	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

// BuildExitXRayJSON returns xray JSON for the exit node (splithttp inbound -> freedom).
// xrayLogLevel is Xray log.loglevel; empty means warning.
func BuildExitXRayJSON(spec *Spec, strat mimic.Strategy, xrayLogLevel string) ([]byte, error) {
	if spec.Role != RoleExit {
		return nil, fmt.Errorf("config: expected exit role")
	}
	w := resolveXrayWire(spec)
	if xrayLogLevel == "" {
		xrayLogLevel = "warning"
	}
	inStream := splithttpInboundStream(spec, strat, w)

	cfg := map[string]any{
		"log": map[string]any{"loglevel": xrayLogLevel},
		"inbounds": []any{
			map[string]any{
				"tag":      w.ExitInboundTunnelTag,
				"listen":   spec.ListenAddress,
				"port":     spec.VLESSPort,
				"protocol": "vless",
				"settings": map[string]any{
					"clients": []any{
						map[string]any{
							"id":    spec.Exit.TunnelUUID,
							"email": w.ExitTunnelUserLabel,
						},
					},
					"decryption": w.VLESSEncryption,
				},
				"streamSettings": inStream,
				"sniffing": map[string]any{
					"enabled":      true,
					"destOverride": w.SniffingDestOverride,
				},
			},
		},
		"outbounds": []any{
			map[string]any{
				"tag":      w.OutboundDirectTag,
				"protocol": "freedom",
				"settings": map[string]any{},
			},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": w.OutboundDirectTag},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}
