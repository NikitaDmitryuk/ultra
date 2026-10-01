package adminapi

import (
	"context"
	"errors"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

type selectionExitRepo struct {
	exits.Repo
	nodes []exits.Node
}

func (r selectionExitRepo) List(context.Context) ([]exits.Node, error) { return r.nodes, nil }

func TestClientRoutesMatchAutoAndFixedPolicies(t *testing.T) {
	primary := "primary"
	nodes := []exits.Node{{ID: primary, Enabled: true, Priority: 100}, {ID: "reserve", Enabled: true, Priority: 200}}
	manager, err := exits.NewManager(selectionExitRepo{nodes: nodes}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	selector := exits.NewSelector(func(_ context.Context, n exits.Node) exits.Health { return exits.Health{InternetOK: n.ID == "reserve"} })
	for range 2 {
		selector.ProbeAndSelect(context.Background(), nodes)
	}
	server := &Server{exits: manager, selector: selector}
	owner := auth.User{UUID: "owner", PreferredExitID: &primary, Routes: []auth.RouteCredential{{UUID: "location", ExitID: &primary, Published: true}}}
	selected, effective, _, _ := server.clientExitSelection(owner)
	if selected != nil || effective != "reserve" || server.routeReason(owner) != "" {
		t.Fatal("legacy preference affected Auto", selected, effective, server.routeReason(owner))
	}
	profiles := server.profileRoutes(owner)
	if len(profiles) != 1 || profiles[0]["effective_exit_id"] != primary {
		t.Fatal("fixed profile followed Auto", profiles)
	}
	owner.ExcludedExitIDs = []string{primary}
	if profiles = server.profileRoutes(owner); profiles[0]["effective_exit_id"] != auth.BlockedExit {
		t.Fatal("fixed profile bypassed quota", profiles)
	}
	var applications auth.RouteApplications
	users := auth.ExpandRoutes([]auth.User{owner})
	for i := range users {
		users[i].EffectiveExitID = users[i].SelectExit(nodes, "reserve", selector.HealthSnapshot())
	}
	applications.Begin(users)
	applications.Finish(nil)
	server.RouteStatus = applications.Status
	owner.ExcludedExitIDs = []string{primary, "reserve"}
	users = auth.ExpandRoutes([]auth.User{owner})
	for i := range users {
		users[i].EffectiveExitID = users[i].SelectExit(nodes, "reserve", selector.HealthSnapshot())
	}
	applications.Begin(users)
	applications.Finish(errors.New("fixture"))
	_, effective, _, _ = server.clientExitSelection(owner)
	if effective != "reserve" || server.routeApplication(owner).State != "error" {
		t.Fatal("reported unconfirmed route", effective)
	}
	applications.Begin(users)
	applications.Finish(nil)
	_, effective, _, _ = server.clientExitSelection(owner)
	if effective != auth.BlockedExit {
		t.Fatal("retry did not confirm route", effective)
	}
}
