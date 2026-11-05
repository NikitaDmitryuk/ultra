package installplan

import (
	"encoding/json"
	"strings"
	"testing"
)

func exitPingPlan(t *testing.T, values map[string]string) *InstallPlan {
	t.Helper()
	base := canonicalFixture()
	base["REUSE_BRIDGE_SPEC"] = "false"
	base["REALITY_DEST"] = "example.com:443"
	for key, value := range values {
		base[key] = value
	}
	p, err := CanonicalValuesToPlan(base)
	if err != nil {
		t.Fatal(err)
	}
	return completePlanFixture(p)
}

func TestExitPingDeploymentDefaultsAndPropagation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		values := map[string]string{}
		if enabled {
			values = map[string]string{"EXIT_PING_ENABLE": "1", "HAPP_EXIT_PING_ENABLE": "true", "HAPP_PROVIDER_ID": "fixture-provider"}
		}
		p := exitPingPlan(t, values)
		desired, err := RenderDesiredState(p)
		if err != nil {
			t.Fatal(err)
		}
		bridge := desired.BridgeSpecObject
		if bridge.ExitPing != enabled || bridge.HappExitPing != enabled {
			t.Fatal("bridge feature policy changed")
		}
		for _, exit := range desired.ExitSpecObjects {
			if exit.ExitPing != enabled || exit.HappExitPing || exit.HappProviderID != "" {
				t.Fatal("exit lost dataplane policy or received client publication metadata")
			}
		}
		if !enabled && strings.Contains(string(desired.BridgeSpec), "exit_ping") {
			t.Fatal("default feature unexpectedly enabled")
		}
		encoded, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		var restored InstallPlan
		if err := json.Unmarshal(encoded, &restored); err != nil {
			t.Fatal(err)
		}
		if enabled && (restored.Features.ExitPing == nil || !*restored.Features.ExitPing) {
			t.Fatal("serialized deployment lost opt-in")
		}
	}
}

func TestExitPingReusePreservesAndExplicitRollbackDisables(t *testing.T) {
	p := exitPingPlan(
		t,
		map[string]string{"EXIT_PING_ENABLE": "true", "HAPP_EXIT_PING_ENABLE": "true", "HAPP_PROVIDER_ID": "fixture-provider"},
	)
	initial, err := RenderDesiredState(p)
	if err != nil {
		t.Fatal(err)
	}
	p.Bridge.ReuseSpec = true
	p.Features.ExitPing, p.Features.HappExitPing, p.Features.HappProviderID = nil, nil, nil
	opts := RenderOptions{
		ExistingBridge:     initial.BridgeSpecObject,
		ExistingAdminToken: initial.AdminToken,
		PriorBootstrap:     initial.Bootstrap,
	}
	reused, err := RenderDesiredStateWithOptions(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !reused.BridgeSpecObject.HappExitPing || reused.BridgeSpecObject.HappProviderID != "fixture-provider" {
		t.Fatal("omitted settings erased installed policy")
	}
	for _, exit := range reused.ExitSpecObjects {
		if !exit.ExitPing {
			t.Fatal("reused bridge did not enable exit responder")
		}
	}
	off, empty := false, ""
	p.Features.ExitPing, p.Features.HappExitPing, p.Features.HappProviderID = &off, &off, &empty
	rolledBack, err := RenderDesiredStateWithOptions(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.BridgeSpecObject.ExitPing || rolledBack.BridgeSpecObject.HappExitPing ||
		rolledBack.BridgeSpecObject.HappProviderID != "" {
		t.Fatal("explicit rollback ignored")
	}
	if !initial.BridgeSpecObject.HappExitPing {
		t.Fatal("reuse mutated original snapshot")
	}
}

func TestExitPingDeploymentRejectsInvalidPolicy(t *testing.T) {
	for _, values := range []map[string]string{
		{"HAPP_EXIT_PING_ENABLE": "true"},
		{"EXIT_PING_ENABLE": "false", "HAPP_EXIT_PING_ENABLE": "true", "HAPP_PROVIDER_ID": "fixture"},
		{"EXIT_PING_ENABLE": "true", "HAPP_EXIT_PING_ENABLE": "true", "HAPP_PROVIDER_ID": ""},
		{"HAPP_PROVIDER_ID": "bad\r\nHeader"},
	} {
		if _, err := RenderDesiredState(exitPingPlan(t, values)); err == nil {
			t.Fatal("invalid publication policy accepted")
		}
	}
	for _, key := range []string{"EXIT_PING_ENABLE", "HAPP_EXIT_PING_ENABLE"} {
		base := canonicalFixture()
		base[key] = "not-a-bool"
		if _, err := CanonicalValuesToPlan(base); err == nil {
			t.Fatalf("malformed %s accepted", key)
		}
	}
}
