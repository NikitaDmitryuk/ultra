package main

import (
	"context"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

func TestPersonalRouteSnapshotAllExitsQuotaFallbackAndUnknown(t *testing.T) {
	r, _, p := runtimeFixture(t)
	commitFixture(t, r, p)
	r.selector = exits.NewSelector(func(context.Context, exits.Node) exits.Health { return exits.Health{InternetOK: true} })
	for range 3 {
		r.selector.ProbeAndSelect(context.Background(), r.nodes)
	}
	// Selector uses real timestamps; runtime fixture clock is fixed just before it.
	r.now = time.Now
	view := r.personalRouteSnapshot()
	if len(view) != 1 || !view[0].Known || !view[0].Available || view[0].QuotaBlocked {
		t.Fatal("healthy route snapshot", view)
	}
	r.users[0].ExcludedExitIDs = []string{"a"}
	r.users[0].ExitExclusionReasons = map[string]string{"a": "monthly_user_limit_exhausted"}
	view = r.personalRouteSnapshot()
	if !view[0].Known || view[0].QuotaBlocked || !view[0].Available {
		t.Fatal("one exhausted exit hid fallback", view)
	}
	r.users[0].ExcludedExitIDs = []string{"a", "b"}
	r.users[0].ExitExclusionReasons["b"] = "exit_budget_exhausted"
	view = r.personalRouteSnapshot()
	if !view[0].Known || !view[0].QuotaBlocked || view[0].Available {
		t.Fatal("all routes quota", view)
	}
	r.users[0].ExitExclusionReasons["b"] = "provider_unavailable"
	view = r.personalRouteSnapshot()
	if view[0].Known {
		t.Fatal("provider API failure treated as quota or outage", view)
	}
	r.users[0].ExcludedExitIDs = nil
	r.selector = exits.NewSelector(nil)
	view = r.personalRouteSnapshot()
	if view[0].Known {
		t.Fatal("unmeasured health treated as outage", view)
	}
}
