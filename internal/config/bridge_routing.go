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

func prependGeositeBlockRules(spec *Spec, w xrayWireResolved, rules []any) []any {
	doms := normalizeGeositeDomains(spec.GeositeBlockTags)
	if len(doms) == 0 {
		return rules
	}
	blockRule := map[string]any{
		"type":        "field",
		"domain":      doms,
		"outboundTag": w.OutboundBlockTag,
	}
	return append([]any{blockRule}, rules...)
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
	rules = prependGeositeBlockRules(spec, w, rules)
	return "IPIfNonMatch", rules
}

// effectiveGeositeDirectTags: nil/omitted → no geosite-based direct rule (runetfreedom geosite.dat
// often has no "ru" list; use geoip + TLD regex by default). Non-empty list adds geosite:* rules
// only for tags present in your geosite.dat (e.g. v2fly domain-list-community includes "ru").
func effectiveGeositeDirectTags(s *Spec) []string {
	if s.GeositeDirectTags == nil {
		return nil
	}
	if len(s.GeositeDirectTags) == 0 {
		return nil
	}
	var out []string
	for _, t := range s.GeositeDirectTags {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// effectiveGeoipDirectTags: nil → default ["ru","private"]; explicit [] → disabled.
func effectiveGeoipDirectTags(s *Spec) []string {
	if s.GeoipDirectTags == nil {
		return []string{"ru", "private"}
	}
	if len(s.GeoipDirectTags) == 0 {
		return nil
	}
	var out []string
	for _, t := range s.GeoipDirectTags {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func ruDirectTLDRegexEnabled(s *Spec) bool {
	if s.RuDirectTLDRegex == nil {
		return true
	}
	return *s.RuDirectTLDRegex
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
	var domainDirect []string
	if gs := effectiveGeositeDirectTags(spec); len(gs) > 0 {
		domainDirect = append(domainDirect, normalizeGeositeDomains(gs)...)
	}
	if ruDirectTLDRegexEnabled(spec) {
		domainDirect = append(domainDirect,
			`regexp:.*\.ru$`,
			`regexp:.*\.su$`,
			`regexp:.*\.xn--p1ai$`,
		)
	}
	if len(domainDirect) > 0 {
		rules = append(rules, map[string]any{
			"type": "field", "domain": domainDirect, "outboundTag": w.OutboundDirectTag,
		})
	}
	if ips := normalizeGeoipIPs(effectiveGeoipDirectTags(spec)); len(ips) > 0 {
		rules = append(rules, map[string]any{
			"type": "field", "ip": ips, "outboundTag": w.OutboundDirectTag,
		})
	}
	rules = append(rules, map[string]any{
		"type": "field", "network": "tcp,udp", "outboundTag": w.OutboundExitTag,
	})
	rules = prependGeositeBlockRules(spec, w, rules)
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

// BridgeNeedsBlockOutbound is true when spec references geosite block rules (blackhole outbound required).
func BridgeNeedsBlockOutbound(spec *Spec) bool {
	return len(normalizeGeositeDomains(spec.GeositeBlockTags)) > 0
}
