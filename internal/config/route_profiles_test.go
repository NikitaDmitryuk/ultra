package config

import (
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"net/url"
	"testing"
)

func TestLocationProfilesPreserveLegacyAndDistinctCredentials(t *testing.T) {
	spec := bridgeSpecForAntiCensorTest()
	user := auth.User{UUID: "00000000-0000-0000-0000-000000000011", Kind: "vless"}
	original, e := BuildClientProfiles(spec, user)
	if e != nil {
		t.Fatal(e)
	}
	exit := "00000000-0000-0000-0000-000000000012"
	user.Routes = []auth.RouteCredential{{UUID: "00000000-0000-0000-0000-000000000013", LocationID: "fra", Name: "Frankfurt", ExitID: &exit, Published: true}}
	profiles, e := BuildClientProfiles(spec, user)
	if e != nil {
		t.Fatal(e)
	}
	if len(profiles) != 2*len(original) {
		t.Fatal("missing location profiles")
	}
	for i := range original {
		if profiles[i].ID != original[i].ID {
			t.Fatal("legacy profile id changed")
		}
		uri, e := url.Parse(profiles[i].VLESSURI)
		if e != nil || uri.User.Username() != user.UUID {
			t.Fatal("legacy credential changed")
		}
	}
	uri, e := url.Parse(profiles[len(original)].VLESSURI)
	if e != nil || uri.User.Username() != user.Routes[0].UUID {
		t.Fatal("location credential not exported")
	}
	user.Routes[0].Published = false
	profiles, e = BuildClientProfiles(spec, user)
	if e != nil || len(profiles) != len(original) {
		t.Fatal("unapplied location published")
	}
	expanded := auth.ExpandRoutes([]auth.User{user})
	if len(expanded) != 2 || expanded[1].PreferredExitID == nil || *expanded[1].PreferredExitID != exit {
		t.Fatal("explicit route not pinned")
	}
	if user.PreferredExitID != nil {
		t.Fatal("explicit profile changed default")
	}
}
