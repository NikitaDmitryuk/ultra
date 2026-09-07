package auth

import (
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"testing"
)

func TestQuotaFallbackDoesNotBypassAmsterdam(t *testing.T) {
	pref := "fra"
	u := User{PreferredExitID: &pref, FallbackExitID: "ams", ExcludedExitIDs: []string{"fra"}}
	nodes := []exits.Node{{ID: "fra"}, {ID: "ams"}, {ID: "other"}}
	health := map[string]exits.Health{"fra": {Eligible: true, PreferredReady: true}, "ams": {Eligible: true, PreferredReady: true}, "other": {Eligible: true, PreferredReady: true}}
	if got := u.SelectExit(nodes, "other", health); got != "ams" {
		t.Fatal(got)
	}
	health["ams"] = exits.Health{}
	if got := u.SelectExit(nodes, "other", health); got != BlockedExit {
		t.Fatal("unavailable fallback bypassed", got)
	}
	u.ExcludedExitIDs = nil
	if got := u.SelectExit(nodes, "other", health); got != "fra" {
		t.Fatal("restoration failed", got)
	}
	u.ExcludedExitIDs = []string{"fra", "ams"}
	for _, a := range ExpandRoutes([]User{u}) {
		if a.SelectExit(nodes, "fra", health) != BlockedExit {
			t.Fatal("quota bypassed")
		}
	}
}
