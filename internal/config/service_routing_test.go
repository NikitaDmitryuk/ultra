package config

import (
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"strings"
	"testing"
)

func TestMonitorServiceRoutingFailsClosed(t *testing.T) {
	u := auth.User{UUID: "monitor", ServiceTargets: []string{"https://probe.example/health"}, EffectiveExitID: "us"}
	rules := serviceRouting([]auth.User{u}, "to-exit-nl", "block")
	if len(rules) != 2 {
		t.Fatal(rules)
	}
	allow := rules[0].(map[string]any)
	deny := rules[1].(map[string]any)
	if allow["outboundTag"] != "to-exit-us" || allow["port"] != "443" || allow["network"] != "tcp" || deny["outboundTag"] != "block" {
		t.Fatal(rules)
	}
	b, _ := json.Marshal(rules)
	if !strings.Contains(string(b), "full:probe.example") {
		t.Fatal(string(b))
	}
	u.EffectiveExitID = auth.BlockedExit
	rules = serviceRouting([]auth.User{u}, "to-exit-nl", "block")
	if rules[0].(map[string]any)["outboundTag"] != "block" {
		t.Fatal("exhausted service allowed fallback", rules)
	}
}
