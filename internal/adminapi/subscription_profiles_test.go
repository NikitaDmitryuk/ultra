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
	uris, err := subscriptionURIs(spec, user, nodes, health)
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
	uris, err = subscriptionURIs(spec, user, nodes, health)
	if err != nil || len(uris) != 1 {
		t.Fatal("unpublished location leaked")
	}
}

func TestSubscriptionUsesSingleConfiguredXHTTPTransport(t *testing.T) {
	spec := &config.Spec{PublicHost: "example.com", VLESSPort: 443, Reality: config.RealitySpec{ServerNames: []string{"example.com"}, PublicKey: "test"}, AntiCensor: &config.AntiCensorSpec{PublicXHTTPPort: 8443}}
	exit := "nl"
	user := auth.User{UUID: "owner", Routes: []auth.RouteCredential{{UUID: "alias", ExitID: &exit, Published: true}}}
	uris, e := subscriptionURIs(spec, user, []exits.Node{{ID: exit, Enabled: true, CountryCode: "NL"}}, map[string]exits.Health{exit: {Eligible: true}})
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
	fallback, e := config.BuildSubscriptionExport(spec, user)
	if e != nil {
		t.Fatal(e)
	}
	if fallback.VLESSURI != legacy.VLESSURI {
		t.Fatal("unconfigured listener published")
	}
}
