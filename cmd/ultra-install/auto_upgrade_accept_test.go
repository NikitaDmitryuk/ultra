package main

import (
	"context"
	"errors"
	"testing"
)

func TestAcceptanceLostDrainResponseReleasesReservedGate(t *testing.T) {
	drainErr := errors.New("lost_drain_response")
	reserved := false
	released := false
	activated := false
	err := withAutoAcceptanceGate(context.Background(), func(_ context.Context, phase string, drain bool) error {
		if phase == "applying" {
			reserved = true
			if !drain {
				t.Fatal("drain not requested")
			}
			return drainErr
		}
		if phase == "released" {
			if !reserved {
				t.Fatal("release before reservation")
			}
			released = true
			return nil
		}
		t.Fatal("unexpected phase")
		return nil
	}, func() error { activated = true; return nil })
	if !errors.Is(err, drainErr) || !released || activated {
		t.Fatalf("lost response stranded reservation: %v released=%v activated=%v", err, released, activated)
	}
}
func TestAcceptanceReleaseFailureCannotClaimSuccess(t *testing.T) {
	releaseErr := errors.New("release_unconfirmed")
	err := withAutoAcceptanceGate(context.Background(), func(_ context.Context, phase string, _ bool) error {
		if phase == "released" {
			return releaseErr
		}
		return nil
	}, func() error { return nil })
	if !errors.Is(err, releaseErr) {
		t.Fatal("unconfirmed release reported accepted")
	}
}
