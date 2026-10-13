package installplan

import "testing"

func TestAutomationVersionBoundary(t *testing.T) {
	legacy := LegacyValuesToPlan(map[string]string{"BRIDGE": "192.0.2.1", "EXIT": "192.0.2.2", "REALITY_DEST": "example.com:443"})
	if legacy.SchemaVersion != 1 || legacy.FullAutomation() {
		t.Fatal("legacy install acquired new required behavior")
	}
	legacy.SchemaVersion = 2
	legacy.Bridge.ReuseSpec = true
	if err := validateAutomation(legacy); err == nil {
		t.Fatal("v2 accepted without full automation")
	}
	legacy.Automation = &AutomationConfig{Version: "v2.3.4", ReleaseDir: "/release", AgeRecipient: "age1fixture", BridgeProvider: "a", BridgeIPv4: "192.0.2.1", BridgeURL: "https://example.com/happ", KnownHostsFile: "/pins", StaticNodes: []AutomationNode{{Name: "US", Address: "192.0.2.2", Provider: "b"}}}
	if err := validateAutomation(legacy); err != nil {
		t.Fatal(err)
	}
	if !legacy.SSH.StrictHostKey || legacy.Automation.ReadinessTimeoutSec == 0 {
		t.Fatal("missing strict defaults")
	}
	legacy.Automation.Version = "latest"
	if validateAutomation(legacy) == nil {
		t.Fatal("mutable release accepted")
	}
	legacy.Automation.Version = "v2.3.4"
	legacy.Automation.StaticNodes[0].Provider = "a"
	if validateAutomation(legacy) != nil {
		t.Fatal("single-provider installation must reach explicit incomplete readiness, not fail structural validation")
	}
}

func TestCleanAutomationRequiresExplicitStaticBudgets(t *testing.T) {
	p := LegacyValuesToPlan(map[string]string{"BRIDGE": "192.0.2.1", "EXIT": "192.0.2.2", "REALITY_DEST": "example.com:443"})
	p.Bridge.ReuseSpec = false
	p.SchemaVersion = 2
	p.Bot.Enabled = true
	p.Database.Enabled = true
	p.Automation = &AutomationConfig{Version: "v2", ReleaseDir: "/release", AgeRecipient: "age1fixture", BridgeProvider: "a", BridgeIPv4: "192.0.2.1", BridgeURL: "https://example.com/happ", KnownHostsFile: "/pins", StaticNodes: []AutomationNode{{Name: "NL", Address: "192.0.2.2", Provider: "a"}}, Ingress: &AutomationIngress{Domain: "vpn.example.com", Email: "a@example.com", Path: "/connect"}}
	if err := validateAutomation(p); err == nil {
		t.Fatal("clean install accepted absent budget")
	}
	p.Automation.StaticNodes[0].Budget = &StaticBudget{MonthlyBytes: 100000000000, IsFallback: true}
	if err := validateAutomation(p); err != nil {
		t.Fatal(err)
	}
	p.Automation.StaticNodes[0].Budget.MonthlyBytes = 0
	if err := validateAutomation(p); err == nil {
		t.Fatal("zero budget accepted")
	}
	p.Automation.StaticNodes[0].Budget.MonthlyBytes = 100000000000
	p.Automation.StaticNodes = append(p.Automation.StaticNodes, AutomationNode{Name: "US", Address: "192.0.2.3", Provider: "b", Budget: &StaticBudget{MonthlyBytes: 100000000000, IsFallback: true}})
	if err := validateAutomation(p); err == nil {
		t.Fatal("multiple fallbacks accepted")
	}
	p.Automation.StaticNodes = p.Automation.StaticNodes[:1]
	p.Automation.StaticNodes[0].Budget = nil
	p.Bridge.ReuseSpec = true
	if err := validateAutomation(p); err != nil {
		t.Fatal("adoption must defer absent budget check to database", err)
	}
}
