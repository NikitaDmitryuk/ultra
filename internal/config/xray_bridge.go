package config

import (
	"encoding/json"
	"fmt"

	"github.com/NikitaDmitryuk/ultra/auth"
	"github.com/NikitaDmitryuk/ultra/mimic"
)

// BuildBridgeXRayJSON returns a full xray JSON config for the bridge role.
// xrayLogLevel is passed to Xray's log.loglevel (e.g. debug, warning, none); empty means warning.
func BuildBridgeXRayJSON(spec *Spec, users []auth.User, strat mimic.Strategy, xrayLogLevel string) ([]byte, error) {
	if spec.Role != RoleBridge {
		return nil, fmt.Errorf("config: expected bridge role")
	}
	clients := make([]map[string]any, 0, len(users))
	for _, u := range users {
		if u.UUID == "" {
			continue
		}
		email := u.Name
		if email == "" {
			email = u.UUID[:8]
		}
		clients = append(clients, map[string]any{
			"id":    u.UUID,
			"email": email,
		})
	}

	if xrayLogLevel == "" {
		xrayLogLevel = "warning"
	}
	inStream := bridgeInboundStream(spec)
	outStream := splithttpOutboundStream(spec, strat)

	cfg := map[string]any{
		"log": map[string]any{"loglevel": xrayLogLevel},
		"inbounds": []any{
			map[string]any{
				"tag":      "vless-in",
				"listen":   spec.ListenAddress,
				"port":     spec.VLESSPort,
				"protocol": "vless",
				"settings": map[string]any{
					"clients":    clients,
					"decryption": "none",
					"fallbacks":  []any{},
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
				"tag":      "to-exit",
				"protocol": "vless",
				"settings": map[string]any{
					"vnext": []any{
						map[string]any{
							"address": spec.Exit.Address,
							"port":    spec.Exit.Port,
							"users": []any{
								map[string]any{
									"id":         spec.Exit.TunnelUUID,
									"encryption": "none",
								},
							},
						},
					},
				},
				"streamSettings": outStream,
			},
			map[string]any{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]any{},
			},
		},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "to-exit"},
			},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}
