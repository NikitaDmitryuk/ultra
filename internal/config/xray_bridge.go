package config

import (
	"encoding/json"
	"fmt"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

// statsAPIListen returns the gRPC API listen address from spec, defaulting to "127.0.0.1:10085".
func statsAPIListen(spec *Spec) string {
	if spec.Stats != nil && spec.Stats.APIListen != "" {
		return spec.Stats.APIListen
	}
	return "127.0.0.1:10085"
}

// BuildBridgeXRayJSON returns a full xray JSON config for the bridge role.
// xrayLogLevel is passed to Xray's log.loglevel (e.g. debug, warning, none); empty means warning.
// When spec.Stats is set, per-user traffic stats and the Xray gRPC API inbound are enabled.
func BuildBridgeXRayJSON(spec *Spec, users []auth.User, strat mimic.Strategy, xrayLogLevel string) ([]byte, error) {
	if spec.Role != RoleBridge {
		return nil, fmt.Errorf("config: expected bridge role")
	}
	statsEnabled := spec.Stats != nil && spec.Database != nil

	w := resolveXrayWire(spec)
	clients := make([]map[string]any, 0, len(users))
	for _, u := range users {
		if u.UUID == "" {
			continue
		}
		// When stats are enabled use the UUID as email so the stats key is
		// "user>>>UUID>>>traffic>>>uplink/downlink" and maps back unambiguously.
		email := u.Name
		if email == "" || statsEnabled {
			email = u.UUID
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
	var outStream map[string]any
	if spec.UsesGRPC() {
		outStream = grpcOutboundStream(spec, strat)
	} else {
		outStream = splithttpOutboundStream(spec, strat, w)
	}

	domainStrategy, routeRules := buildBridgeRouting(spec)
	needsBlock := BridgeNeedsBlockOutbound(spec)

	// Prepend the API routing rule when stats are enabled.
	if statsEnabled {
		apiRule := map[string]any{
			"type":        "field",
			"inboundTag":  []any{"api"},
			"outboundTag": "api",
		}
		routeRules = append([]any{apiRule}, routeRules...)
	}

	routing := map[string]any{
		"domainStrategy": domainStrategy,
		"rules":          routeRules,
	}
	if spec.SplitRoutingEnabled() {
		routing["domainMatcher"] = w.DomainMatcherSplit
	}

	apiListenHost, apiListenPort, _ := splitHostPort(statsAPIListen(spec))

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
	if statsEnabled {
		inbounds = append(inbounds, map[string]any{
			"tag":      "api",
			"listen":   apiListenHost,
			"port":     apiListenPort,
			"protocol": "dokodemo-door",
			"settings": map[string]any{"address": apiListenHost},
		})
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

	outbounds := []any{
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
	}
	if statsEnabled {
		outbounds = append(outbounds, map[string]any{
			"tag":      "api",
			"protocol": "freedom",
			"settings": map[string]any{},
		})
	}
	if needsBlock {
		outbounds = append(outbounds, map[string]any{
			"tag":      w.OutboundBlockTag,
			"protocol": "blackhole",
			"settings": map[string]any{},
		})
	}

	cfg := map[string]any{
		"log":       map[string]any{"loglevel": xrayLogLevel},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing":   routing,
	}
	if dns := buildDNSSection(spec); dns != nil {
		cfg["dns"] = dns
	}
	if statsEnabled {
		cfg["api"] = map[string]any{
			"tag":      "api",
			"services": []any{"StatsService"},
		}
		cfg["stats"] = map[string]any{}
		cfg["policy"] = map[string]any{
			"levels": map[string]any{
				"0": map[string]any{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
				},
			},
		}
	}
	return json.MarshalIndent(cfg, "", "  ")
}
