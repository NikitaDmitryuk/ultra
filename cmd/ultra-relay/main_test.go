package main

import (
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

func TestAutoAndLocationEffectiveRoutes(t *testing.T) {
	pref := "b"
	owner := auth.User{UUID: "auto", PreferredExitID: &pref, Routes: []auth.RouteCredential{{UUID: "location", ExitID: &pref}}}
	users := auth.ExpandRoutes([]auth.User{owner})
	nodes := []exits.Node{{ID: "a", Enabled: true}, {ID: "b", Enabled: true}}
	got := applyEffectiveUserExits(users, nodes, "a", map[string]exits.Health{"a": {Eligible: true}, "b": {}})
	if got[0].EffectiveExitID != "a" || got[1].EffectiveExitID != "b" {
		t.Fatal(got)
	}
	if users[0].EffectiveExitID != "" || users[1].EffectiveExitID != "" {
		t.Fatal("mutated manager cache")
	}
	got = applyEffectiveUserExits(users, nodes[:1], "a", nil)
	if got[0].EffectiveExitID != "a" || got[1].EffectiveExitID != auth.BlockedExit {
		t.Fatal("deleted location escaped", got)
	}
}
