package config

import (
	"encoding/json"
	"fmt"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

// statsAPIListen returns the gRPC API listen address from spec, defaulting to "127.0.0.1:10085".
func statsAPIListen(spec *Spec) string {
	if spec.Stats != nil && spec.Stats.APIListen != "" {
		return spec.Stats.APIListen
	}
	return "127.0.0.1:10085"
}

// HealthProbe* are the loopback dokodemo-door coordinates the bridge spawns so that
// the admin API can measure exit→internet latency over the full tunnel.
const (
	HealthProbeInboundTag   = "health-probe"
	HealthProbeListenAddr   = "127.0.0.1"
	HealthProbePort         = 11800
	HealthProbeTargetHost   = "1.1.1.1"
	HealthProbeTargetPort   = 443
	HealthProbeListenIPPort = "127.0.0.1:11800"
)

// BuildBridgeXRayJSON returns a full xray JSON config for the bridge role.
// exitNodes lists enabled upstream exits; activeExitID selects routing target (empty uses legacy to-exit / spec.Exit).
// xrayLogLevel is passed to Xray's log.loglevel (e.g. debug, warning, none); empty means warning.
// When spec.Stats is set, per-user traffic stats and the Xray gRPC API inbound are enabled.
func BuildBridgeXRayJSON(
	spec *Spec,
	users []auth.User,
	exitNodes []exits.Node,
	activeExitID string,
	strat mimic.Strategy,
	xrayLogLevel string,
) ([]byte, error) {
	if spec.Role != RoleBridge {
		return nil, fmt.Errorf("config: expected bridge role")
	}
	statsEnabled := spec.Stats != nil && spec.Database != nil

	w := resolveXrayWire(spec)
	clients := make([]map[string]any, 0, len(users))
	xhttpClients := make([]map[string]any, 0, len(users))
	for _, u := range users {
		if u.UUID == "" {
			continue
		}
		if u.Kind == "socks5" {
			continue
		}
		// When stats are enabled use the UUID as email so the stats key is
		// "user>>>UUID>>>traffic>>>uplink/downlink" and maps back unambiguously.
		email := u.Name
		if email == "" || statsEnabled {
			email = u.UUID
		}
		client := map[string]any{
			"id":    u.UUID,
			"email": email,
		}
		if flow := spec.PublicVLESSFlow(); flow != "" {
			client["flow"] = flow
		}
		clients = append(clients, client)
		xhttpClients = append(xhttpClients, map[string]any{
			"id":    u.UUID,
			"email": email,
		})
	}

	if xrayLogLevel == "" {
		xrayLogLevel = "warning"
	}
	inStream := bridgeInboundStream(spec)
	buildOutStream := func(pinnedPeerCertSHA256 string) map[string]any {
		if spec.UsesGRPC() {
			return grpcOutboundStream(spec, strat, pinnedPeerCertSHA256)
		}
		return splithttpOutboundStream(spec, strat, w, pinnedPeerCertSHA256)
	}

	domainStrategy, routeRules := buildBridgeRouting(spec, resolveActiveExitTag(activeExitID, w))
	needsBlock := BridgeNeedsBlockOutbound(spec)
	activeTag := resolveActiveExitTag(activeExitID, w)

	// Prepend the API routing rule when stats are enabled.
	if statsEnabled {
		apiRule := map[string]any{
			"type":        "field",
			"inboundTag":  []any{"api"},
			"outboundTag": "api",
		}
		routeRules = append([]any{apiRule}, routeRules...)
	}

	// Prepend a health-probe routing rule that forces dokodemo-door traffic onto the
	// bridge→exit tunnel, regardless of split routing.
	probeRule := map[string]any{
		"type":        "field",
		"inboundTag":  []any{HealthProbeInboundTag},
		"outboundTag": activeTag,
	}
	routeRules = append([]any{probeRule}, routeRules...)

	if p := spec.botTelegramProxy(); p != nil {
		botRule := map[string]any{
			"type":        "field",
			"inboundTag":  []any{BotTelegramProxyInboundTag},
			"outboundTag": activeTag,
		}
		routeRules = append([]any{botRule}, routeRules...)
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
	if spec.AntiCensor != nil && spec.AntiCensor.PublicXHTTPPort > 0 && !spec.DevMode {
		xhttpStream := bridgeInboundStream(spec)
		xhttpStream["network"] = "xhttp"
		xhttpStream["xhttpSettings"] = map[string]any{
			"path":         fallbackXHTTPPath(spec),
			"mode":         "auto",
			"xPaddingSize": fallbackXHTTPPadding(spec),
		}
		inbounds = append(inbounds, map[string]any{
			"tag":      w.InboundVLESSTag + "-xhttp",
			"listen":   spec.ListenAddress,
			"port":     spec.AntiCensor.PublicXHTTPPort,
			"protocol": "vless",
			"settings": map[string]any{
				"clients":    xhttpClients,
				"decryption": w.VLESSEncryption,
				"fallbacks":  []any{},
			},
			"streamSettings": xhttpStream,
			"sniffing": map[string]any{
				"enabled":      true,
				"destOverride": w.SniffingDestOverride,
			},
		})
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

	// Internal dokodemo-door forwarding to a stable internet target through the
	// bridge→exit tunnel; used by /v1/health to verify exit's internet access.
	inbounds = append(inbounds, map[string]any{
		"tag":      HealthProbeInboundTag,
		"listen":   HealthProbeListenAddr,
		"port":     HealthProbePort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{
			"address": HealthProbeTargetHost,
			"port":    HealthProbeTargetPort,
			"network": "tcp",
		},
	})
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
	if p := spec.botTelegramProxy(); p != nil {
		inbounds = append(inbounds, map[string]any{
			"tag":      BotTelegramProxyInboundTag,
			"listen":   botTelegramProxyListen(p),
			"port":     botTelegramProxyPort(p),
			"protocol": "socks",
			"settings": map[string]any{
				"auth": "noauth",
				"udp":  false,
			},
		})
	}
	for _, u := range users {
		if u.Kind != "socks5" || u.SocksPort == nil || *u.SocksPort <= 0 {
			continue
		}
		if u.SocksUsername == "" || u.SocksPassword == "" {
			continue
		}
		tag := "socks-" + u.UUID
		inbounds = append(inbounds, map[string]any{
			"tag":      tag,
			"listen":   "0.0.0.0",
			"port":     *u.SocksPort,
			"protocol": "socks",
			"settings": map[string]any{
				"auth": w.SocksAuth,
				"accounts": []any{
					map[string]any{"user": u.SocksUsername, "pass": u.SocksPassword},
				},
				"udp": true,
			},
			"sniffing": map[string]any{
				"enabled":      true,
				"destOverride": w.SniffingDestOverride,
			},
		})
	}

	outbounds := buildBridgeExitOutbounds(spec, exitNodes, activeExitID, w, buildOutStream)
	outbounds = append(outbounds,
		map[string]any{
			"tag":      w.OutboundDirectTag,
			"protocol": "freedom",
			"settings": map[string]any{},
		},
	)
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
			"system": map[string]any{
				"statsInboundUplink":   true,
				"statsInboundDownlink": true,
			},
			"levels": map[string]any{
				"0": map[string]any{
					"statsUserUplink":   true,
					"statsUserDownlink": true,
					"statsUserOnline":   true,
				},
			},
		}
	}
	return json.MarshalIndent(cfg, "", "  ")
}
