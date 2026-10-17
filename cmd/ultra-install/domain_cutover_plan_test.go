package main

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
)

func TestDomainCutoverPlannerPreservesSeparateDialAndTLSNames(t *testing.T) {
	prior := &config.Spec{
		Role:             config.RoleBridge,
		GatewayVLESSPort: 18082,
		PrimaryXHTTP: &config.PrimaryXHTTPIngress{
			Host:               "old.example.com",
			BackendPort:        18080,
			PublicXHTTPTLSSpec: config.PublicXHTTPTLSSpec{Port: 443, ServerName: "old.example.com", Path: "/existing"},
		},
	}
	before, _ := json.Marshal(prior)
	desired := domainCutoverDesired{
		Subscription: "sync.example.com",
		VPN:          "edge.example.com",
		PublicHost:   "dial.example.net",
		Zone:         "example.com",
		Email:        "ops@example.com",
		BotDomain:    "backend.example.com",
		BotPort:      8444,
		BridgeIPv4:   "192.0.2.1",
	}
	owned := map[string]any{"records": map[string]any{"subscription": "owned"}}
	vars, err := buildDomainCutoverVariables(
		desired,
		prior,
		"/private/upgrade/domains",
		"/private/lease",
		"https://old.example.com/subscription/fixture",
		"fixture-key",
		owned,
	)
	if err != nil {
		t.Fatal(err)
	}
	ingress := vars["ultra_ingress"].(map[string]any)
	for key, want := range map[string]any{"domain": desired.VPN, "subscription_domain": desired.Subscription, "public_host": desired.PublicHost, "path": "/existing", "backend_port": 18080, "gateway_port": 18082, "staging_port": 18443, "status_port": 18082, "experimental_port": 5543, "forward_host": ""} {
		if ingress[key] != want {
			t.Fatalf("%s=%v, want %v", key, ingress[key], want)
		}
	}
	if vars["ultra_bot_domain"] != desired.BotDomain || vars["ultra_lock_directory"] != "/private/lease" ||
		!reflect.DeepEqual(vars["ultra_dns_receipt_seed"], owned) {
		t.Fatal("lost caller-owned identity or evidence")
	}
	if vars["ultra_dns_api_key"] != "fixture-key" ||
		vars["ultra_dns_config"].(map[string]any)["vpn_name"] != "edge" ||
		vars["ultra_dns_config"].(map[string]any)["api_key_file"] != "/etc/ultra-recovery/dns-api-key" {
		t.Fatal("dial host replaced DNS TLS identity")
	}
	after, _ := json.Marshal(prior)
	if string(before) != string(after) {
		t.Fatal("planner mutated observed spec")
	}
	again, err := buildDomainCutoverVariables(
		desired,
		prior,
		"/private/upgrade/domains",
		"/private/lease",
		"https://old.example.com/subscription/fixture",
		"fixture-key",
		owned,
	)
	if err != nil || !reflect.DeepEqual(vars, again) {
		t.Fatal("planner is not deterministic")
	}
	delta := cutoverDelta(desired.Subscription, desired.VPN, desired.Zone, desired.PublicHost)
	if delta["PUBLIC_HOST"] != desired.PublicHost || delta["VPN_DOMAIN"] != desired.VPN {
		t.Fatal("canonical projection conflates dial host and TLS identity")
	}
}

func TestDomainCutoverPlannerRejectsMissingCallerEvidence(t *testing.T) {
	for _, test := range []string{"unpublished", "relative-directory", "invalid-host", "missing-probe", "missing-key", "missing-ownership", "foreign-zone"} {
		t.Run(test, func(t *testing.T) {
			prior := &config.Spec{
				Role: config.RoleBridge,
				PrimaryXHTTP: &config.PrimaryXHTTPIngress{
					PublicXHTTPTLSSpec: config.PublicXHTTPTLSSpec{Port: 443, Path: "/existing"},
					BackendPort:        18080,
				},
			}
			desired := domainCutoverDesired{
				Subscription: "sync.example.com",
				VPN:          "edge.example.com",
				PublicHost:   "192.0.2.1",
				Zone:         "example.com",
				BotPort:      8444,
				BridgeIPv4:   "192.0.2.1",
			}
			directory, probe, key := "/private/domains", "https://old.example.com/fixture", "fixture-key"
			owned := map[string]any{"records": "fixture"}
			switch test {
			case "unpublished":
				published := false
				prior.PrimaryXHTTP.Published = &published
			case "relative-directory":
				directory = "relative"
			case "invalid-host":
				desired.PublicHost = "https://edge.example.com"
			case "missing-probe":
				probe = ""
			case "missing-key":
				key = ""
			case "missing-ownership":
				owned = nil
			case "foreign-zone":
				desired.VPN = "edge.example.net"
			}
			vars, err := buildDomainCutoverVariables(desired, prior, directory, "/private/lease", probe, key, owned)
			if err == nil || vars != nil {
				t.Fatal("accepted missing or incompatible evidence")
			}
		})
	}
}
