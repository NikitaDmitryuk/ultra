package config

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
)

func TestPrimaryIngressPublicationAndListeners(t *testing.T) {
	s := bridgeSpecForAntiCensorTest()
	s.PrimaryXHTTP = &PrimaryXHTTPIngress{Host: "bridge.example", BackendPort: 18080, PublicXHTTPTLSSpec: PublicXHTTPTLSSpec{Port: 443, ServerName: "site.example", Path: "/connect"}}
	s.LegacyPublicEnabled = BoolPtr(false)
	s.GatewayVLESSPort = 18081
	u := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", IsActive: true}
	exp, err := BuildSubscriptionExport(s, u, "")
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse(exp.VLESSURI)
	if uri.User.Username() != u.UUID || uri.Query().Get("security") != "tls" || uri.Query().Get("flow") != "" || uri.Hostname() != "bridge.example" {
		t.Fatal("wrong primary export")
	}
	strat, _ := mimic.New("steamlike")
	raw, err := BuildBridgeXRayJSON(s, []auth.User{u}, nil, "", strat, "error")
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(raw, &cfg)
	found := map[string]bool{}
	for _, v := range cfg["inbounds"].([]any) {
		in := v.(map[string]any)
		tag := in["tag"].(string)
		found[tag] = true
		if tag == "vless-in-primary-xhttp" || tag == "vless-in-gateway" {
			if in["listen"] != "127.0.0.1" {
				t.Fatal("backend public")
			}
		}
	}
	if found["vless-in"] || !found["vless-in-primary-xhttp"] || !found["vless-in-gateway"] {
		t.Fatal("wrong listener set", found)
	}
	s.PrimaryXHTTP.Published = BoolPtr(false)
	s.LegacyPublicEnabled = nil
	old, err := BuildSubscriptionExport(s, u, "")
	if err != nil {
		t.Fatal(err)
	}
	uri, _ = url.Parse(old.VLESSURI)
	if uri.Query().Get("security") == "tls" {
		t.Fatal("staged ingress published")
	}
}

func TestExperimentalDescriptorValidation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	p := ExperimentalProfile{Host: "bridge.example", StatusPort: 18082, Endpoint: PublicXHTTPTLSSpec{Port: 5543, ServerName: "site.example", Path: "/test"}}
	write := func() {
		raw, _ := json.Marshal(p)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	if _, err := LoadExperimentalProfile(path); err != nil {
		t.Fatal(err)
	}
	p.Endpoint.KeyFile = "/secret"
	write()
	if _, err := LoadExperimentalProfile(path); err == nil {
		t.Fatal("private descriptor accepted")
	}
	p.Endpoint.KeyFile = ""
	p.Endpoint.Path = "/test?query"
	write()
	if _, err := LoadExperimentalProfile(path); err == nil {
		t.Fatal("invalid path accepted")
	}
}

func TestPrimaryIngressForwardingEntries(t *testing.T) {
	s := bridgeSpecForAntiCensorTest()
	s.PrimaryXHTTP = &PrimaryXHTTPIngress{Host: "bridge.example", BackendPort: 18080, PublicXHTTPTLSSpec: PublicXHTTPTLSSpec{Port: 443, ServerName: "site.example", Path: "/connect", Fingerprint: "firefox"}}
	s.LegacyPublicEnabled = BoolPtr(false)
	s.PublicEntries = []PublicEntry{{ID: "tls", Host: "backup.example", TCPPort: 8443, XHTTPTLSPort: 9443}, {ID: "legacy", Host: "legacy.example", TCPPort: 8443}}
	profiles, err := BuildClientProfiles(s, auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", IsActive: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 {
		t.Fatalf("got %d profiles, want primary and TLS forwarder", len(profiles))
	}
	uri, err := url.Parse(profiles[1].VLESSURI)
	if err != nil {
		t.Fatal(err)
	}
	if uri.Host != "backup.example:9443" || uri.Query().Get("sni") != "site.example" || uri.Query().Get("fp") != "firefox" {
		t.Fatal("forwarding entry must preserve TLS settings and use its own endpoint")
	}
	if s.PrimaryXHTTP.Host != "bridge.example" || s.PrimaryXHTTP.Port != 443 {
		t.Fatal("primary endpoint mutated")
	}
}
