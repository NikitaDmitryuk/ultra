package config

import (
	"encoding/json"
	"fmt"

	"github.com/NikitaDmitryuk/ultra/mimic"
)

// BuildExitXRayJSON returns xray JSON for the exit node (splithttp inbound -> freedom).
// xrayLogLevel is Xray log.loglevel; empty means warning.
func BuildExitXRayJSON(spec *Spec, strat mimic.Strategy, xrayLogLevel string) ([]byte, error) {
	if spec.Role != RoleExit {
		return nil, fmt.Errorf("config: expected exit role")
	}
	if xrayLogLevel == "" {
		xrayLogLevel = "warning"
	}
	inStream := splithttpInboundStream(spec, strat)

	cfg := map[string]any{
		"log": map[string]any{"loglevel": xrayLogLevel},
		"inbounds": []any{
			map[string]any{
				"tag":      "vless-splithttp",
				"listen":   spec.ListenAddress,
				"port":     spec.VLESSPort,
				"protocol": "vless",
				"settings": map[string]any{
					"clients": []any{
						map[string]any{
							"id":    spec.Exit.TunnelUUID,
							"email": "tunnel",
						},
					},
					"decryption": "none",
				},
				"streamSettings": inStream,
				"sniffing": map[string]any{
					"enabled":      true,
					"destOverride": []string{"http", "tls", "quic"},
				},
			},
		},
		"outbounds": []any{
			map[string]any{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]any{},
			},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "direct"},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}
