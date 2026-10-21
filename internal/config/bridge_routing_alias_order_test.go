package config

import (
	"slices"
	"testing"
)

func TestCountryAliasPreservesSplitRuleOrder(t *testing.T) {
	for _, domains := range [][]string{nil, {"domain:foreign.example"}} {
		for _, target := range []string{"to-exit-other", "block"} {
			spec := &Spec{
				SplitRouting: BoolPtr(true),
				RoutingMode:  RoutingModeRUDirect,
				DomainExit:   domains,
				DomainDirect: []string{"domain:local.example"},
			}
			_, rules := buildBridgeRouting(spec, "to-exit-default", map[string]string{"alias": target})
			catchall, direct, ru := -1, -1, -1
			for i, raw := range rules {
				rule := raw.(map[string]any)
				if rule["outboundTag"] == target && rule["network"] == "tcp,udp" {
					catchall = i
				}
				if values, ok := rule["domain"].([]string); ok {
					if slices.Contains(values, "domain:local.example") {
						direct = i
					}
					if slices.Contains(values, "domain:ru") {
						ru = i
					}
				}
			}
			if catchall < 0 || direct < 0 || direct >= catchall {
				t.Fatalf("direct rule intercepted: direct=%d catchall=%d domains=%v target=%s", direct, catchall, domains, target)
			}
			if ru >= 0 && ru >= catchall {
				t.Fatalf("RU direct intercepted: ru=%d catchall=%d", ru, catchall)
			}
		}
	}
}
