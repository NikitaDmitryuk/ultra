package config

import (
	"strings"
)

func buildBridgeRouting(spec *Spec) (domainStrategy string, rules []any) {
	w := resolveXrayWire(spec)
	if !spec.SplitRoutingEnabled() {
		return "AsIs", []any{
			map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": w.OutboundExitTag},
		}
	}
	mode := spec.RoutingMode
	if mode == "" {
		mode = RoutingModeBlocklist
	}
	switch mode {
	case RoutingModeBlocklist:
		return buildBlocklistRouting(spec, w)
	case RoutingModeRUDirect:
		return buildRUDirectRouting(spec, w)
	default:
		return "AsIs", []any{
			map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": w.OutboundExitTag},
		}
	}
}

func buildBlocklistRouting(spec *Spec, w xrayWireResolved) (string, []any) {
	var rules []any
	for _, d := range spec.DomainDirect {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		rules = append(rules, map[string]any{
			"type": "field", "domain": []string{d}, "outboundTag": w.OutboundDirectTag,
		})
	}
	for _, d := range spec.DomainExit {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		rules = append(rules, map[string]any{
			"type": "field", "domain": []string{d}, "outboundTag": w.OutboundExitTag,
		})
	}
	tags := spec.GeositeExitTags
	if len(tags) == 0 {
		tags = []string{"ru-blocked-all"}
	}
	if doms := normalizeGeositeDomains(tags); len(doms) > 0 {
		rules = append(rules, map[string]any{
			"type": "field", "domain": doms, "outboundTag": w.OutboundExitTag,
		})
	}
	if ips := normalizeGeoipIPs(spec.GeoipExitTags); len(ips) > 0 {
		rules = append(rules, map[string]any{
			"type": "field", "ip": ips, "outboundTag": w.OutboundExitTag,
		})
	}
	rules = append(rules, map[string]any{
		"type": "field", "network": "tcp,udp", "outboundTag": w.OutboundDirectTag,
	})
	return "IPIfNonMatch", rules
}

func buildRUDirectRouting(spec *Spec, w xrayWireResolved) (string, []any) {
	var rules []any
	for _, d := range spec.DomainExit {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		rules = append(rules, map[string]any{
			"type": "field", "domain": []string{d}, "outboundTag": w.OutboundExitTag,
		})
	}
	for _, d := range spec.DomainDirect {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		rules = append(rules, map[string]any{
			"type": "field", "domain": []string{d}, "outboundTag": w.OutboundDirectTag,
		})
	}
	rules = append(rules, map[string]any{
		"type": "field", "ip": []string{w.RuDirectGeoipMatcher}, "outboundTag": w.OutboundDirectTag,
	})
	rules = append(rules, map[string]any{
		"type": "field", "network": "tcp,udp", "outboundTag": w.OutboundExitTag,
	})
	return "IPIfNonMatch", rules
}

func normalizeGeositeDomains(tags []string) []string {
	var out []string
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if strings.Contains(t, ":") {
			out = append(out, t)
			continue
		}
		out = append(out, "geosite:"+t)
	}
	return out
}

func normalizeGeoipIPs(tags []string) []string {
	var out []string
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if strings.HasPrefix(t, "geoip:") {
			out = append(out, t)
			continue
		}
		out = append(out, "geoip:"+t)
	}
	return out
}
