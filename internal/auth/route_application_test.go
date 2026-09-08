package auth

import (
	"errors"
	"testing"
)

func TestRouteConfirmationRetainsPreviousOnFailure(t *testing.T) {
	var r RouteApplications
	users := []User{{UUID: "owner", EffectiveExitID: "ams"}}
	if r.Status("owner").State == "applied" {
		t.Fatal("unconfirmed startup")
	}
	r.Begin(users)
	r.Finish(nil)
	users[0].EffectiveExitID = "atl"
	r.Begin(users)
	if s := r.Status("owner"); s.State != "applying" || s.EffectiveExit != "ams" {
		t.Fatal(s)
	}
	r.Finish(errors.New("fixture"))
	if s := r.Status("owner"); s.State != "error" || s.EffectiveExit != "ams" || !r.Pending() {
		t.Fatal(s)
	}
	r.Begin(users)
	r.Finish(nil)
	s := r.Status("owner")
	if s.State != "applied" || s.EffectiveExit != "atl" || r.Pending() {
		t.Fatal(s)
	}
	r.Begin(users)
	r.Finish(nil)
	if r.Status("owner").Revision != s.Revision {
		t.Fatal("unchanged route revision")
	}
	users[0].EffectiveExitID = "ams"
	r.Begin(users)
	r.Finish(nil)
	if r.Status("owner").EffectiveExit != "ams" {
		t.Fatal("return route")
	}
}
