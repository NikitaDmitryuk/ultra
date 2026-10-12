package adminapi

import (
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"net/url"
	"testing"
)

func TestSubscriptionOnlyAutoAndAvailableCountries(t *testing.T) {
	spec := &config.Spec{DevMode: true, PublicHost: "example.com", VLESSPort: 443, PublicEntries: []config.PublicEntry{{ID: "other", Host: "other.example.com", TCPPort: 443}}}
	// The public subscription uses the primary listener even when technical exports have alternatives.
	a, b, c := "a", "b", "c"
	user := auth.User{UUID: "owner", Routes: []auth.RouteCredential{{UUID: "nl-a", ExitID: &a, Published: true}, {UUID: "nl-b", ExitID: &b, Published: true}, {UUID: "de", ExitID: &c, Published: true}}}
	nodes := []exits.Node{{ID: a, Enabled: true, Priority: 100, CountryCode: "NL"}, {ID: b, Enabled: true, Priority: 200, CountryCode: "NL"}, {ID: c, Enabled: true, CountryCode: "DE"}}
	health := map[string]exits.Health{a: {Eligible: true}, b: {Eligible: true}, c: {Eligible: false}}
	uris, err := subscriptionURIs(spec, user, nodes, health, "")
	if err != nil || len(uris) != 2 {
		t.Fatalf("got %d profiles, err=%v", len(uris), err)
	}
	for i, want := range []string{"Автоматически", "Нидерланды"} {
		u, err := url.Parse(uris[i])
		if err != nil || u.Fragment != want {
			t.Fatalf("profile %d label mismatch", i)
		}
		credential := "owner"
		if i == 1 {
			credential = "nl-a"
		}
		if u.User.Username() != credential {
			t.Fatal("wrong credential")
		}
	}
	user.Routes[0].Published = false
	user.Routes[1].Published = false
	uris, err = subscriptionURIs(spec, user, nodes, health, "")
	if err != nil || len(uris) != 1 {
		t.Fatal("unpublished location leaked")
	}
}

func TestSubscriptionUsesSingleConfiguredXHTTPTransport(t *testing.T) {
	spec := &config.Spec{PublicHost: "example.com", VLESSPort: 443, Reality: config.RealitySpec{ServerNames: []string{"example.com"}, PublicKey: "test"}, AntiCensor: &config.AntiCensorSpec{PublicXHTTPPort: 8443}}
	exit := "nl"
	user := auth.User{UUID: "owner", Routes: []auth.RouteCredential{{UUID: "alias", ExitID: &exit, Published: true}}}
	uris, e := subscriptionURIs(spec, user, []exits.Node{{ID: exit, Enabled: true, CountryCode: "NL"}}, map[string]exits.Health{exit: {Eligible: true}}, "")
	if e != nil || len(uris) != 2 {
		t.Fatalf("count=%d err=%v", len(uris), e)
	}
	for _, raw := range uris {
		u, e := url.Parse(raw)
		if e != nil {
			t.Fatal(e)
		}
		q := u.Query()
		if q.Get("type") != "xhttp" || q.Get("security") != "reality" || q.Get("flow") != "" || u.Port() != "8443" || q.Get("extra") == "" {
			t.Fatal("wrong subscription transport")
		}
	}
	legacy, e := config.BuildClientExport(spec, user)
	if e != nil {
		t.Fatal(e)
	}
	u, e := url.Parse(legacy.VLESSURI)
	if e != nil || u.Query().Get("type") != "tcp" || u.Port() != "443" {
		t.Fatal("legacy export changed")
	}
	spec.AntiCensor = nil
	fallback, e := config.BuildSubscriptionExport(spec, user, "")
	if e != nil {
		t.Fatal(e)
	}
	if fallback.VLESSURI != legacy.VLESSURI {
		t.Fatal("unconfigured listener published")
	}
}

func TestHappProfilesPreserveRouteCredentials(t *testing.T) {
	spec := &config.Spec{DevMode: true, PublicHost: "primary.example", VLESSPort: 443, SubscriptionBridges: []config.SubscriptionBridge{
		{ID: "a", Host: "a.example", Port: 443, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ServerName: "example.com"},
		{ID: "b", Host: "b.example", Port: 443, PublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ServerName: "example.com"},
	}}
	exit := "nl"
	user := auth.User{UUID: "owner", Routes: []auth.RouteCredential{{UUID: "country", ExitID: &exit, Published: true}}}
	profiles, err := subscriptionHapp(spec, user, []exits.Node{{ID: exit, Enabled: true, CountryCode: "NL"}}, map[string]exits.Health{exit: {Eligible: true}})
	if err != nil || len(profiles) != 2 {
		t.Fatalf("profiles=%d err=%v", len(profiles), err)
	}
	for i, profile := range profiles {
		for _, raw := range profile["outbounds"].([]any) {
			out := raw.(map[string]any)
			if out["protocol"] != "vless" {
				continue
			}
			credential := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)["id"]
			want := "owner"
			if i == 1 {
				want = "country"
			}
			if credential != want {
				t.Fatal("changed route UUID", credential)
			}
		}
	}
	if user.UUID != "owner" || user.Routes[0].UUID != "country" {
		t.Fatal("mutated credentials")
	}
}

func TestSubscriptionXHTTPTLSPreservesCredentials(t *testing.T) {
	spec := &config.Spec{PublicHost: "bridge.example", VLESSPort: 443,
		Reality:        config.RealitySpec{ServerNames: []string{"example.com"}, PublicKey: "test"},
		PublicXHTTPTLS: &config.PublicXHTTPTLSSpec{Port: 5443, ServerName: "vpn.example", Path: "/connect", Mode: "stream-up"}}
	exit := "nl"
	user := auth.User{UUID: "owner", Routes: []auth.RouteCredential{{UUID: "country", ExitID: &exit, Published: true}}}
	nodes := []exits.Node{{ID: exit, Enabled: true, CountryCode: "NL"}}
	health := map[string]exits.Health{exit: {Eligible: true}}
	before, err := subscriptionURIs(spec, user, nodes, health, "")
	if err != nil {
		t.Fatal(err)
	}
	uris, err := subscriptionURIs(spec, user, nodes, health, "xhttp-tls")
	if err != nil || len(uris) != 2 {
		t.Fatalf("profiles=%d err=%v", len(uris), err)
	}
	for i, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		old, _ := url.Parse(before[i])
		q := u.Query()
		if u.User.Username() != old.User.Username() || u.Fragment != old.Fragment || u.Hostname() != old.Hostname() {
			t.Fatal("changed identity or location")
		}
		if q.Get("type") != "xhttp" || q.Get("security") != "tls" || q.Get("flow") != "" || q.Get("sni") != "vpn.example" || u.Port() != "5443" {
			t.Fatal("wrong TLS transport")
		}
	}
	if len(before) != 2 {
		t.Fatal("unselected TLS listener leaked into subscription")
	}
	after, err := subscriptionURIs(spec, user, nodes, health, "")
	if err != nil || after[0] != before[0] || after[1] != before[1] {
		t.Fatal("default subscription changed")
	}
	spec.PublicXHTTPTLS = nil
	if _, err := subscriptionURIs(spec, user, nodes, health, "xhttp-tls"); err == nil {
		t.Fatal("published absent listener")
	}
}
