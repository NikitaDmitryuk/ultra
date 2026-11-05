package config

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/xtls/xray-core/core"
)

func TestExitPingValidation(t *testing.T) {
	for _, tc := range []struct {
		spec  Spec
		valid bool
	}{
		{Spec{}, true},
		{Spec{Role: RoleExit, ExitPing: true}, true},
		{Spec{Role: RoleBridge, ExitPing: true, HappExitPing: true, HappProviderID: "provider-01_test"}, true},
		{Spec{Role: RoleBridge, ExitPing: true, HappProviderID: strings.Repeat("a", 128)}, true},
		{Spec{Role: RoleExit, ExitPing: true, HappExitPing: true, HappProviderID: "provider"}, false},
		{Spec{Role: RoleBridge, HappExitPing: true, HappProviderID: "provider"}, false},
		{Spec{Role: RoleBridge, ExitPing: true, HappExitPing: true}, false},
	} {
		if err := tc.spec.ValidateExitPing(); (err == nil) != tc.valid {
			t.Fatalf("%+v: %v", tc.spec, err)
		}
	}
	for _, id := range []string{" ", "a\rb", "a\nb", "a:b", "provider.example", "тест", strings.Repeat("a", 129)} {
		s := Spec{HappProviderID: id}
		if s.ValidateExitPing() == nil {
			t.Fatalf("unsafe ID accepted: %q", id)
		}
	}
	data, err := json.Marshal(Spec{})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"exit_ping", "happ_provider_id", "happ_exit_ping"} {
		if bytes.Contains(data, []byte(field)) {
			t.Fatalf("default publishes %s", field)
		}
	}
}

func TestExitPingRoutesRespectRestrictions(t *testing.T) {
	strategy, _ := mimic.New("apijson")
	s := &Spec{Role: RoleBridge, DevMode: true, VLESSPort: 443, PublicHost: "198.51.100.7", ExitPing: true, SplitRouting: BoolPtr(false)}
	users := []auth.User{
		{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", EffectiveExitID: auth.BlockedExit},
		{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ef", EffectiveExitID: "alternate"},
		{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653f0", ServiceTargets: []string{"https://example.com/"}},
	}
	data, err := BuildBridgeXRayJSON(s, users, nil, "", strategy, "error")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	excluded := cfg["inbounds"].([]any)[0].(map[string]any)["sniffing"].(map[string]any)["ipsExcluded"].([]any)
	if len(excluded) != 2 || excluded[0] != ExitPingIPv4 || excluded[1] != s.PublicHost {
		t.Fatalf("synthetic or existing public-host sniffing exclusion lost: %v", excluded)
	}
	rules := cfg["routing"].(map[string]any)["rules"].([]any)
	// Service allow/block, user-specific probes, default probe, reserved-address
	// block, health inbound, then ordinary forwarding.
	if len(rules) != 10 {
		t.Fatalf("unexpected rules: %s", data)
	}
	for i, tag := range map[int]string{1: "block", 2: "block", 3: "to-exit-alternate", 4: "to-exit", 5: exitPingBlockTag} {
		if rules[i].(map[string]any)["outboundTag"] != tag {
			t.Fatalf("rule %d: %+v", i, rules[i])
		}
	}
	for _, warp := range []bool{false, true} {
		s.Role = RoleExit
		s.Exit.TunnelUUID = users[0].UUID
		s.ExitCertPaths.CertFile, s.ExitCertPaths.KeyFile = testCertificate(t)
		s.AntiCensor = &AntiCensorSpec{WARPProxy: warp}
		for _, port := range []int{0, 19123} {
			data, err = BuildExitXRayJSONWithPingPort(s, strategy, "error", port)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = core.LoadConfig("json", bytes.NewReader(data)); err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(data, &cfg); err != nil {
				t.Fatal(err)
			}
			rules = cfg["routing"].(map[string]any)["rules"].([]any)
			tag := exitPingBlockTag
			if port > 0 {
				tag = exitPingOutboundTag
			}
			if rules[0].(map[string]any)["outboundTag"] != tag {
				t.Fatal("probe falls through to ordinary/WARP route")
			}
		}
	}
}

func TestHappExitPingObservatory(t *testing.T) {
	s := &Spec{Role: RoleBridge, DevMode: true, ExitPing: true, HappExitPing: true, HappProviderID: "test"}
	profile, err := BuildHappProfile(s, auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee"}, "Auto")
	if err != nil {
		t.Fatal(err)
	}
	ping := profile["burstObservatory"].(map[string]any)["pingConfig"].(map[string]any)
	if ping["destination"] != ExitPingURL || ping["interval"] != "10s" || ping["sampling"] != 1 || ping["timeout"] != "5s" {
		t.Fatalf("changed Auto cadence: %+v", ping)
	}
	s.HappExitPing = false
	profile, err = BuildHappProfile(s, auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee"}, "Auto")
	if err != nil {
		t.Fatal(err)
	}
	if profile["burstObservatory"].(map[string]any)["pingConfig"].(map[string]any)["destination"] != "https://www.google.com/generate_204" {
		t.Fatal("default Auto changed")
	}
}
