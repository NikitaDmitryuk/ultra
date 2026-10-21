package cloudinstall

import (
	"errors"
	"fmt"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/db"
)

func TestRouteRemovalErrorPreservesLastEnabledGuard(t *testing.T) {
	last := fmt.Errorf("disable: %w", db.ErrExitLastEnabled)
	mapped := routeRemovalError(last)
	if !errors.Is(mapped, db.ErrExitLastEnabled) || !errors.Is(mapped, cloud.ErrLastEnabledExit) {
		t.Fatalf("last-enabled reason lost: %v", mapped)
	}
	unknown := errors.New("private failure")
	if got := routeRemovalError(unknown); got != unknown || errors.Is(got, cloud.ErrLastEnabledExit) {
		t.Fatalf("unknown error was reclassified: %v", got)
	}
}
