package auth

import (
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

func TestAutoAndFixedExitPolicies(t *testing.T) {
	primary := "fra"
	nodes := []exits.Node{{ID: primary, Enabled: true, Priority: 100}, {ID: "ams", Enabled: true, Priority: 200}, {ID: "other", Enabled: true, Priority: 300}}
	healthy := map[string]exits.Health{"fra": {Eligible: true, PreferredReady: true}, "ams": {Eligible: true, PreferredReady: true}, "other": {Eligible: true, PreferredReady: true}}
	for _, tt := range []struct {
		name     string
		fixed    bool
		active   string
		excluded []string
		health   map[string]exits.Health
		nodes    []exits.Node
		want     string
	}{
		{name: "auto ignores saved preference", active: "ams", health: healthy, nodes: nodes, want: "ams"},
		{name: "auto honors stability window", active: "ams", health: map[string]exits.Health{"fra": {Eligible: true}, "ams": {Eligible: true}}, nodes: nodes[:2], want: "ams"},
		{name: "auto skips quota by priority", active: "fra", excluded: []string{"fra"}, health: healthy, nodes: nodes, want: "ams"},
		{name: "auto finds another allowed exit", active: "fra", excluded: []string{"fra", "ams"}, health: healthy, nodes: nodes, want: "other"},
		{name: "auto blocks when all down", active: "fra", health: map[string]exits.Health{"fra": {}, "ams": {}, "other": {}}, nodes: nodes, want: BlockedExit},
		{name: "auto blocks when reserve excluded", active: "ams", excluded: []string{"ams"}, health: map[string]exits.Health{"fra": {}, "ams": {Eligible: true}}, nodes: nodes[:2], want: BlockedExit},
		{name: "fixed healthy", fixed: true, active: "ams", health: healthy, nodes: nodes, want: "fra"},
		{name: "fixed down stays pinned", fixed: true, active: "ams", health: map[string]exits.Health{"fra": {}, "ams": {Eligible: true}}, nodes: nodes, want: "fra"},
		{name: "fixed quota blocks", fixed: true, active: "ams", excluded: []string{"fra"}, health: healthy, nodes: nodes, want: BlockedExit},
		{name: "fixed deleted blocks", fixed: true, active: "ams", health: healthy, nodes: nodes[1:], want: BlockedExit},
		{name: "fixed disabled blocks", fixed: true, active: "ams", health: healthy, nodes: []exits.Node{{ID: "fra"}, nodes[1]}, want: BlockedExit},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := User{PreferredExitID: &primary, FixedExit: tt.fixed, FallbackExitID: "ams", ExcludedExitIDs: tt.excluded}
			if got := u.SelectExit(tt.nodes, tt.active, tt.health); got != tt.want {
				t.Fatalf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestLocationAliasesStayFixedAfterDeletion(t *testing.T) {
	primary := "fra"
	u := User{UUID: "auto", PreferredExitID: &primary, Routes: []RouteCredential{{UUID: "location", ExitID: nil}}}
	expanded := ExpandRoutes([]User{u})
	nodes := []exits.Node{{ID: "ams", Enabled: true}}
	if got := expanded[0].SelectExit(nodes, "ams", nil); got != "ams" {
		t.Fatal(got)
	}
	if got := expanded[1].SelectExit(nodes, "ams", nil); got != BlockedExit {
		t.Fatal("deleted location became Auto", got)
	}
	if u.FixedExit {
		t.Fatal("mutated owner")
	}
}
