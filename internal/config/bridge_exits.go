package config

import (
	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

func resolveActiveExitTag(activeExitID string, w xrayWireResolved) string {
	if activeExitID != "" {
		return exits.OutboundTag(activeExitID)
	}
	return w.OutboundExitTag
}

func findEnabledExit(nodes []exits.Node, id string) (exits.Node, bool) {
	for _, n := range nodes {
		if n.ID == id {
			return n, true
		}
	}
	return exits.Node{}, false
}

func buildBridgeExitOutbounds(spec *Spec, exitNodes []exits.Node, activeExitID string, w xrayWireResolved, buildStream func(pinnedPeerCertSHA256 string) map[string]any) []any {
	enabled := exits.FilterEnabled(exitNodes)
	if len(enabled) == 0 {
		return []any{
			bridgeExitVLESSOutbound(w.OutboundExitTag, spec.Exit.Address, spec.Exit.Port, spec.Exit.TunnelUUID, w, buildStream(spec.Exit.PinnedPeerCertSHA256)),
		}
	}
	var out []any
	for _, n := range enabled {
		out = append(out, bridgeExitVLESSOutbound(exits.OutboundTag(n.ID), n.Address, n.Port, n.TunnelUUID, w, buildStream(n.PinnedPeerCertSHA256)))
	}
	legacyNode, ok := findEnabledExit(enabled, activeExitID)
	if !ok {
		legacyNode, _ = exits.SelectActive(enabled, nil)
	}
	if legacyNode.ID != "" {
		out = append(out, bridgeExitVLESSOutbound(w.OutboundExitTag, legacyNode.Address, legacyNode.Port, legacyNode.TunnelUUID, w, buildStream(legacyNode.PinnedPeerCertSHA256)))
	}
	return out
}

func bridgeExitVLESSOutbound(tag, address string, port int, tunnelUUID string, w xrayWireResolved, outStream map[string]any) map[string]any {
	return map[string]any{
		"tag":      tag,
		"protocol": "vless",
		"settings": map[string]any{
			"vnext": []any{
				map[string]any{
					"address": address,
					"port":    port,
					"users": []any{
						map[string]any{
							"id":         tunnelUUID,
							"encryption": w.VLESSEncryption,
						},
					},
				},
			},
		},
		"streamSettings": outStream,
	}
}
