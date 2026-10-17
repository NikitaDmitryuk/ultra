package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

type forwardMaintenanceDeps struct {
	attach func(context.Context) (context.Context, func(), error)
	stop   func(context.Context) error
}

// Cleanup is a fresh cancellation-independent attempt. Closing its descriptor
// leaves the broker's same-ID applying reservation held even if shutdown fails.
func containForwardUpgradeFailure(ctx context.Context, deps forwardMaintenanceDeps) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Minute)
	defer cancel()
	cleanup, release, err := attachForwardMaintenanceLease(cleanup, deps.attach)
	if err != nil {
		return errors.Join(errors.New("upgrade_forward_maintenance_lease_unavailable"), err)
	}
	defer release()
	if err = deps.stop(cleanup); err != nil {
		return errors.Join(errors.New("upgrade_forward_maintenance_unconfirmed"), err)
	}
	return nil
}

// A previous maintenance worker may briefly own infrastructure.lock while the
// lifecycle is checking. Keep retrying only that expected contention; do not
// retry ownership, transport, or persistence failures as if they were transient.
func attachForwardMaintenanceLease(
	ctx context.Context,
	attach func(context.Context) (context.Context, func(), error),
) (context.Context, func(), error) {
	backoff := 100 * time.Millisecond
	for {
		leased, release, err := attach(ctx)
		if err == nil {
			return leased, release, nil
		}
		if !strings.Contains(err.Error(), "infrastructure_busy") {
			return nil, nil, err
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, nil, ctx.Err()
		case <-timer.C:
		}
		if backoff < 2*time.Second {
			backoff *= 2
			if backoff > 2*time.Second {
				backoff = 2 * time.Second
			}
		}
	}
}

func stopForwardUpgradeFleet(ctx context.Context, inventory map[string]any, lockDirectory, directory, python, executable string) error {
	stage, err := os.MkdirTemp(directory, "forward-maintenance-")
	if err != nil {
		return err
	}
	if err = os.Remove(stage); err != nil {
		return err
	}
	receipt, err := deployansible.RunLocal(
		ctx,
		"contain-upgrade",
		inventory,
		map[string]any{"ultra_lock_directory": lockDirectory, "ultra_lifecycle_id": lifecycleID(directory)},
		stage,
		python,
		executable,
	)
	if err != nil {
		return err
	}
	if receipt.Result.Values["verified"] != true || receipt.Result.Values["maintenance_id"] != lifecycleID(directory) {
		return errors.New("upgrade_forward_maintenance_receipt_invalid")
	}
	return nil
}
