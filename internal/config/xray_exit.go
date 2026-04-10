package config

import (
	"encoding/json"
	"fmt"

	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

// warpProxyPort returns the WARP SOCKS5 listen port (default 40000).
func warpProxyPort(spec *Spec) int {
	if spec.AntiCensor != nil && spec.AntiCensor.WARPProxyPort > 0 {
		return spec.AntiCensor.WARPProxyPort
	}
	return 40000
}

// BuildExitXRayJSON returns xray JSON for the exit node (splithttp inbound -> freedom / WARP).
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

	warpEnabled := spec.AntiCensor != nil && spec.AntiCensor.WARPProxy

	// Build the "direct" outbound: freedom normally, SOCKS5→WARP when WARPProxy is on.
	var directOutbound map[string]any
	if warpEnabled {
		// Route all exit connections through WARP's local SOCKS5 proxy so destination
		// servers see a Cloudflare IP instead of the VPS datacenter IP.
		directOutbound = map[string]any{
			"tag":      w.OutboundDirectTag,
			"protocol": "socks",
			"settings": map[string]any{
				"servers": []any{
					map[string]any{
						"address": "127.0.0.1",
						"port":    warpProxyPort(spec),
					},
				},
			},
		}
	} else {
		directOutbound = map[string]any{
			"tag":      w.OutboundDirectTag,
			"protocol": "freedom",
			"settings": map[string]any{},
		}
	}

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
		"outbounds": []any{directOutbound},
		"routing": map[string]any{
			"domainStrategy": "AsIs",
			"rules": []any{
				map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": w.OutboundDirectTag},
			},
		},
	}

	if dns := buildDNSSection(spec); dns != nil {
		cfg["dns"] = dns
	}

	return json.MarshalIndent(cfg, "", "  ")
}
