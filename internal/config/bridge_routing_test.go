package config

import "testing"

func TestBuildBridgeRoutingAllViaExit(t *testing.T) {
	ds, rules := buildBridgeRouting(&Spec{SplitRouting: BoolPtr(false)})
	if ds != "AsIs" {
		t.Fatalf("domainStrategy: got %q", ds)
	}
	if len(rules) != 1 {
		t.Fatalf("rules len: %d", len(rules))
	}
}

func TestBuildBridgeRoutingBlocklistDefaultGeosite(t *testing.T) {
	ds, rules := buildBridgeRouting(&Spec{
		SplitRouting: BoolPtr(true),
		RoutingMode:  RoutingModeBlocklist,
		GeoAssetsDir: "/tmp/geo",
	})
	if ds != "IPIfNonMatch" {
		t.Fatalf("domainStrategy: got %q", ds)
	}
	var sawGeosite bool
	for _, r := range rules {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if dom, ok := m["domain"].([]string); ok {
			for _, d := range dom {
				if d == "geosite:ru-blocked-all" {
					sawGeosite = true
				}
			}
		}
	}
	if !sawGeosite {
		t.Fatalf("expected geosite:ru-blocked-all in rules: %#v", rules)
	}
}

func TestBuildRUDirectRouting(t *testing.T) {
	ds, rules := buildBridgeRouting(&Spec{
		SplitRouting: BoolPtr(true),
		RoutingMode:  RoutingModeRUDirect,
		GeoAssetsDir: "/tmp/geo",
	})
	if ds != "IPIfNonMatch" {
		t.Fatalf("domainStrategy: got %q", ds)
	}
	var sawRU bool
	for _, r := range rules {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if ips, ok := m["ip"].([]string); ok {
			for _, ip := range ips {
				if ip == "geoip:ru" {
					sawRU = true
				}
			}
		}
	}
	if !sawRU {
		t.Fatalf("expected geoip:ru in rules: %#v", rules)
	}
}
