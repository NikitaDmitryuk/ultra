package config

import (
	"encoding/json"
	"fmt"

	"github.com/nikdmitryuk/ultra/mimic"
)

// BuildExitXRayJSON returns xray JSON for the exit node (splithttp inbound -> freedom).
func BuildExitXRayJSON(spec *Spec, strat mimic.Strategy) ([]byte, error) {
	if spec.Role != RoleExit {
		return nil, fmt.Errorf("config: expected exit role")
	}
	inStream := splithttpInboundStream(spec, strat)

	cfg := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
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
