package config

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/realitykey"
	"github.com/xtls/xray-core/core"
)

func TestHappProfilePublicBridges(t *testing.T) {
	keys, err := realitykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	spec := &Spec{SubscriptionBridges: []SubscriptionBridge{
		{ID: "ekb", Host: "ekb.example.com", Port: 443, PublicKey: keys.PublicKey, ServerName: "example.com", ShortID: "ab12"},
		{ID: "kzn", Host: "kzn.example.com", Port: 8443, PublicKey: keys.PublicKey, ServerName: "example.com", ShortID: "0123456789abcdef", Transport: "xhttp", Path: "/vpn"},
	}}
	u := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee"}
	profile, err := BuildHappProfile(spec, u, "Автоматически")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = core.LoadConfig("json", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	outbounds := profile["outbounds"].([]any)
	if len(outbounds) != 3 || outbounds[0].(map[string]any)["protocol"] != "blackhole" {
		t.Fatal("unsafe default outbound")
	}
	for i, b := range spec.SubscriptionBridges {
		out := outbounds[i+1].(map[string]any)
		if out["tag"] != "bridge-"+b.ID {
			t.Fatal("unstable bridge tag")
		}
		server := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
		if server["address"] != b.Host || server["port"] != b.Port || server["users"].([]any)[0].(map[string]any)["id"] != u.UUID {
			t.Fatal("wrong endpoint or credential")
		}
	}
	balancer := profile["routing"].(map[string]any)["balancers"].([]any)[0].(map[string]any)
	if balancer["fallbackTag"] != "block" || balancer["strategy"].(map[string]any)["type"] != "leastPing" {
		t.Fatal("unsafe failover")
	}
	rules := profile["routing"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 || rules[0].(map[string]any)["network"] != "tcp,udp" || rules[0].(map[string]any)["balancerTag"] != "bridges" {
		t.Fatal("traffic can bypass the fail-closed balancer")
	}
	obs := profile["burstObservatory"].(map[string]any)["pingConfig"].(map[string]any)
	if obs["interval"] != "10s" || obs["sampling"] != 1 || obs["timeout"] != "5s" {
		t.Fatal("wrong probe cadence")
	}
	for _, mutate := range []func(*SubscriptionBridge){
		func(b *SubscriptionBridge) { b.ID = "ekb" },
		func(b *SubscriptionBridge) { b.Port = 0 },
		func(b *SubscriptionBridge) { b.Host = "host/path" },
		func(b *SubscriptionBridge) { b.Transport = "unknown" },
		func(b *SubscriptionBridge) { b.PublicKey = "" },
		func(b *SubscriptionBridge) { b.PublicKey = "not-a-key" },
		func(b *SubscriptionBridge) { b.PublicKey = keys.PublicKey + "=" },
		func(b *SubscriptionBridge) { b.ShortID = "zz" },
		func(b *SubscriptionBridge) { b.ShortID = "abc" },
		func(b *SubscriptionBridge) { b.ShortID = "0123456789abcdef00" },
	} {
		copySpec := *spec
		copySpec.SubscriptionBridges = append([]SubscriptionBridge(nil), spec.SubscriptionBridges...)
		mutate(&copySpec.SubscriptionBridges[1])
		if _, err := BuildHappProfile(&copySpec, u, "test"); err == nil {
			t.Fatal("invalid bridge accepted")
		}
	}
}
