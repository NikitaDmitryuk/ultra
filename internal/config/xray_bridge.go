package config

import (
	"encoding/json"
	"fmt"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

// BuildBridgeXRayJSON returns a full xray JSON config for the bridge role.
// xrayLogLevel is passed to Xray's log.loglevel (e.g. debug, warning, none); empty means warning.
func BuildBridgeXRayJSON(spec *Spec, users []auth.User, strat mimic.Strategy, xrayLogLevel string) ([]byte, error) {
	if spec.Role != RoleBridge {
		return nil, fmt.Errorf("config: expected bridge role")
	}
	w := resolveXrayWire(spec)
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
	outStream := splithttpOutboundStream(spec, strat, w)

	domainStrategy, routeRules := buildBridgeRouting(spec)

	routing := map[string]any{
		"domainStrategy": domainStrategy,
		"rules":          routeRules,
	}
	if spec.SplitRoutingEnabled() {
		routing["domainMatcher"] = w.DomainMatcherSplit
	}

	inbounds := []any{
		map[string]any{
			"tag":      w.InboundVLESSTag,
			"listen":   spec.ListenAddress,
			"port":     spec.VLESSPort,
			"protocol": "vless",
			"settings": map[string]any{
				"clients":    clients,
				"decryption": w.VLESSEncryption,
				"fallbacks":  []any{},
			},
			"streamSettings": inStream,
			"sniffing": map[string]any{
				"enabled":      true,
				"destOverride": w.SniffingDestOverride,
			},
		},
	}
	if s := spec.bridgeSOCKS5(); s != nil {
		inbounds = append(inbounds, map[string]any{
			"tag":      w.InboundSocksTag,
			"listen":   socks5ListenAddress(spec, s),
			"port":     s.Port,
			"protocol": "socks",
			"settings": map[string]any{
				"auth": w.SocksAuth,
				"accounts": []any{
					map[string]any{"user": s.Username, "pass": s.Password},
				},
				"udp": socks5UDPEnabled(s),
			},
			"sniffing": map[string]any{
				"enabled":      true,
				"destOverride": w.SniffingDestOverride,
			},
		})
	}

	cfg := map[string]any{
		"log":      map[string]any{"loglevel": xrayLogLevel},
		"inbounds": inbounds,
		"outbounds": []any{
			map[string]any{
				"tag":      w.OutboundExitTag,
				"protocol": "vless",
				"settings": map[string]any{
					"vnext": []any{
						map[string]any{
							"address": spec.Exit.Address,
							"port":    spec.Exit.Port,
							"users": []any{
								map[string]any{
									"id":         spec.Exit.TunnelUUID,
									"encryption": w.VLESSEncryption,
								},
							},
						},
					},
				},
				"streamSettings": outStream,
			},
			map[string]any{
				"tag":      w.OutboundDirectTag,
				"protocol": "freedom",
				"settings": map[string]any{},
			},
		},
		"routing": routing,
	}
	return json.MarshalIndent(cfg, "", "  ")
}
