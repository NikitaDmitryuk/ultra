package main

import (
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

func TestPreferredExitReadiness(t *testing.T) {
	pref := "b"
	users := []auth.User{{UUID: "user", PreferredExitID: &pref}}
	nodes := []exits.Node{{ID: "a", Enabled: true}, {ID: "b", Enabled: true}}
	for _, ready := range []bool{false, true} {
		got := applyEffectiveUserExits(users, nodes, "a", map[string]exits.Health{"b": {Reachable: true, InternetOK: true, Eligible: true, PreferredReady: ready}})
		want := "a"
		if ready {
			want = "b"
		}
		if got[0].EffectiveExitID != want {
			t.Fatal(got)
		}
		if users[0].EffectiveExitID != "" {
			t.Fatal("mutated manager cache")
		}
	}
	got := applyEffectiveUserExits(users, nodes[:1], "a", nil)
	if got[0].EffectiveExitID != "a" {
		t.Fatal("disabled preference used")
	}
}
