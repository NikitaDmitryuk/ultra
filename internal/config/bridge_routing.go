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
	return "AsIs", rules
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

// ruDirectDefaultServiceDomains returns well-known Russian services that use
// non-.ru/.su/.рф TLDs but should route directly through the bridge in ru_direct mode.
// These supplement the TLD regex (.ru, .su, .xn--p1ai) and geoip:ru rules.
// Users can override specific entries by listing them in spec.DomainExit.
func ruDirectDefaultServiceDomains() []string {
	return []string{
		// VKontakte — Russia's largest social network (primary domain is vk.com, not vk.ru)
		"domain:vk.com",
		"domain:vk.me",
		"domain:vkontakte.com",
		"domain:userapi.com", // VK user-generated content CDN
		"domain:vk-cdn.net",  // VK video CDN
		// Yandex international / CDN
		"domain:yandex.com",
		"domain:yandex.net", // Yandex internal CDN and infrastructure
		"domain:yandex.eu",
		// Mail.ru Group international
		"domain:my.com", // Mail.ru Group's international brand
		// Sberbank / Sber international
		"domain:sber.com",
		// Ozone (uses .ru primary, but also .com for some API traffic)
		"domain:ozon.com",
		// HeadHunter (hh.ru — already caught by TLD, but CDN uses hh.com)
		"domain:hh.com",
	}
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
	// Append default Russian services on non-.ru domains (vk.com, yandex.com, etc.)
	// unless the user has explicitly routed them to exit via DomainExit.
	domainDirect = append(domainDirect, ruDirectDefaultServiceDomains()...)
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
	return "AsIs", rules
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
