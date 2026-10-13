package config

import (
	"bytes"
	"encoding/json"
	"strings"
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

func TestHappMixedTLSRealityEndpoints(t *testing.T) {
	keys, err := realitykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	spec := &Spec{PrimaryXHTTP: &PrimaryXHTTPIngress{Host: "primary.example", Published: BoolPtr(true), BackendPort: 18080, PublicXHTTPTLSSpec: PublicXHTTPTLSSpec{Port: 443, ServerName: "primary.example", Path: "/vpn"}}, SubscriptionBridges: []SubscriptionBridge{
		{ID: "https", Host: "primary.example", Port: 443, Security: "tls", Transport: "xhttp", ServerName: "primary.example", Path: "/vpn"},
		{ID: "reality", Host: "192.0.2.1", Port: 24443, Transport: "tcp", PublicKey: keys.PublicKey, ServerName: "example.com", ShortID: "ab12"},
	}}
	user := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee"}
	profile, err := BuildHappProfile(spec, user, "Auto")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(profile)
	if _, err = core.LoadConfig("json", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	out := profile["outbounds"].([]any)
	for i, security := range []string{"tls", "reality"} {
		endpoint := out[i+1].(map[string]any)
		stream := endpoint["streamSettings"].(map[string]any)
		if stream["security"] != security {
			t.Fatal("wrong transport", stream)
		}
		next := endpoint["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)
		if next["users"].([]any)[0].(map[string]any)["id"] != user.UUID {
			t.Fatal("credentials changed between transports")
		}
	}
	for _, mutate := range []func(*SubscriptionBridge){func(b *SubscriptionBridge) { b.Security = "unknown" }, func(b *SubscriptionBridge) { b.Transport = "tcp" }, func(b *SubscriptionBridge) { b.PublicKey = keys.PublicKey }, func(b *SubscriptionBridge) { b.Path = "" }} {
		candidate := *spec
		candidate.SubscriptionBridges = append([]SubscriptionBridge(nil), spec.SubscriptionBridges...)
		mutate(&candidate.SubscriptionBridges[0])
		if _, err = BuildHappProfile(&candidate, user, "test"); err == nil {
			t.Fatal("invalid TLS descriptor allowed")
		}
	}
}

func TestHappFaultPreviewPreservesBalancerAndIsolation(t *testing.T) {
	keys, err := realitykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	spec := &Spec{SubscriptionBridges: []SubscriptionBridge{
		{ID: "primary", Host: "primary.example", Port: 443, Security: "tls", Transport: "xhttp", ServerName: "primary.example", Path: "/vpn", Fingerprint: "firefox"},
		{ID: "reserve", Host: "reserve.example", Port: 24443, Security: "reality", Transport: "tcp", PublicKey: keys.PublicKey, ServerName: "example.com", ShortID: "ab12", Fingerprint: "firefox"},
	}}
	profiles, err := BuildHappFaultProfiles(spec, auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee"})
	if err != nil || len(profiles) != 4 {
		t.Fatal(err)
	}
	for i, p := range profiles {
		raw, _ := json.Marshal(p)
		if _, err := core.LoadConfig("json", bytes.NewReader(raw)); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(raw, []byte(`"protocol":"freedom"`)) || !bytes.Contains(raw, []byte(`"fallbackTag":"block"`)) || !bytes.Contains(raw, []byte(`"network":"tcp,udp"`)) {
			t.Fatal("lost closed fallback", i)
		}
		out := p["outbounds"].([]any)
		for j := 0; j < 2; j++ {
			address := out[j+1].(map[string]any)["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["address"].(string)
			down := (j == 0 && (i == 1 || i == 3)) || (j == 1 && (i == 2 || i == 3))
			if strings.HasSuffix(address, ".invalid") != down {
				t.Fatal("wrong fault injection", i, j, address)
			}
		}
	}
	if spec.SubscriptionBridges[0].Host != "primary.example" || spec.SubscriptionBridges[1].Host != "reserve.example" {
		t.Fatal("modified source descriptors")
	}
}
