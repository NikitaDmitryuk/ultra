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
	if ds != "AsIs" {
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
	if ds != "AsIs" {
		t.Fatalf("domainStrategy: got %q", ds)
	}
	var sawGeoipRU, sawGeoipPrivate, sawRegexp, lastExit bool
	for i, r := range rules {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if dom, ok := m["domain"].([]string); ok {
			for _, d := range dom {
				switch d {
				case `regexp:.*\.ru$`, `regexp:.*\.su$`, `regexp:.*\.xn--p1ai$`:
					sawRegexp = true
				}
			}
		}
		if ips, ok := m["ip"].([]string); ok {
			for _, ip := range ips {
				switch ip {
				case "geoip:ru":
					sawGeoipRU = true
				case "geoip:private":
					sawGeoipPrivate = true
				}
			}
		}
		if i == len(rules)-1 {
			if tag, _ := m["outboundTag"].(string); tag == "to-exit" {
				if net, _ := m["network"].(string); net == "tcp,udp" {
					lastExit = true
				}
			}
		}
	}
	if !sawGeoipRU {
		t.Fatalf("expected geoip:ru in rules: %#v", rules)
	}
	if !sawGeoipPrivate {
		t.Fatalf("expected geoip:private in rules: %#v", rules)
	}
	if !sawRegexp {
		t.Fatalf("expected TLD regexp matchers in rules: %#v", rules)
	}
	if !lastExit {
		t.Fatalf("expected last rule to send tcp,udp to exit: %#v", rules)
	}
}

func TestBuildRUDirectRoutingExplicitGeosite(t *testing.T) {
	_, rules := buildBridgeRouting(&Spec{
		SplitRouting:      BoolPtr(true),
		RoutingMode:       RoutingModeRUDirect,
		GeoAssetsDir:      "/tmp/geo",
		GeositeDirectTags: []string{"ru"},
	})
	var sawGeositeRU bool
	for _, r := range rules {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if dom, ok := m["domain"].([]string); ok {
			for _, d := range dom {
				if d == "geosite:ru" {
					sawGeositeRU = true
				}
			}
		}
	}
	if !sawGeositeRU {
		t.Fatalf("expected geosite:ru when GeositeDirectTags lists ru: %#v", rules)
	}
}

func TestBuildRUDirectRoutingGeositeDirectDisabled(t *testing.T) {
	empty := []string{}
	_, rules := buildBridgeRouting(&Spec{
		SplitRouting:      BoolPtr(true),
		RoutingMode:       RoutingModeRUDirect,
		GeoAssetsDir:      "/tmp/geo",
		GeositeDirectTags: empty,
		RuDirectTLDRegex:  BoolPtr(false),
		GeoipDirectTags:   []string{"ru"},
	})
	for _, r := range rules {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if dom, ok := m["domain"].([]string); ok {
			for _, d := range dom {
				if d == "geosite:ru" {
					t.Fatalf("geosite:ru should be disabled: %#v", rules)
				}
			}
		}
	}
}

func TestBuildBlocklistPrependsBlockRule(t *testing.T) {
	_, rules := buildBridgeRouting(&Spec{
		SplitRouting:     BoolPtr(true),
		RoutingMode:      RoutingModeBlocklist,
		GeoAssetsDir:     "/tmp/geo",
		GeositeBlockTags: []string{"category-ads-all"},
	})
	if len(rules) < 2 {
		t.Fatalf("expected block + other rules: %#v", rules)
	}
	first, ok := rules[0].(map[string]any)
	if !ok {
		t.Fatal("first rule type")
	}
	if first["outboundTag"] != "block" {
		t.Fatalf("first rule should be block, got %#v", first)
	}
}

func TestBuildRUDirectPrependsBlockRule(t *testing.T) {
	_, rules := buildBridgeRouting(&Spec{
		SplitRouting:     BoolPtr(true),
		RoutingMode:      RoutingModeRUDirect,
		GeoAssetsDir:     "/tmp/geo",
		GeositeBlockTags: []string{"category-ads-all"},
	})
	first, ok := rules[0].(map[string]any)
	if !ok {
		t.Fatal("first rule type")
	}
	if first["outboundTag"] != "block" {
		t.Fatalf("first rule should be block, got %#v", first)
	}
}

func TestBridgeNeedsBlockOutbound(t *testing.T) {
	if BridgeNeedsBlockOutbound(&Spec{GeositeBlockTags: []string{"x"}}) != true {
		t.Fatal("expected true")
	}
	if BridgeNeedsBlockOutbound(&Spec{}) != false {
		t.Fatal("expected false")
	}
}
