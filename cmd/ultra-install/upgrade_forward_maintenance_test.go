package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestForwardFailureContainmentIgnoresCancellationAndRetainsGate(t *testing.T) {
	for _, fail := range []string{"", "attach", "stop"} {
		t.Run(fail, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			var steps []string
			err := containForwardUpgradeFailure(ctx, forwardMaintenanceDeps{
				attach: func(ctx context.Context) (context.Context, func(), error) {
					if ctx.Err() != nil {
						t.Fatal("cleanup inherited cancellation")
					}
					if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) <= 0 {
						t.Fatal("cleanup lacks bounded live deadline")
					}
					steps = append(steps, "attach")
					if fail == "attach" {
						return nil, nil, errors.New("failed")
					}
					return ctx, func() { steps = append(steps, "close descriptor") }, nil
				},
				stop: func(ctx context.Context) error {
					if ctx.Err() != nil {
						t.Fatal("stop inherited cancellation")
					}
					steps = append(steps, "stop")
					if fail == "stop" {
						return errors.New("ansible failed")
					}
					return nil
				},
			})
			if (err != nil) != (fail != "") {
				t.Fatalf("error=%v", err)
			}
			expected := "attach,stop,close descriptor"
			if fail == "attach" {
				expected = "attach"
			}
			if strings.Join(steps, ",") != expected {
				t.Fatal(steps)
			}
			if fail == "stop" && !strings.Contains(err.Error(), "upgrade_forward_maintenance_unconfirmed") {
				t.Fatal(err)
			}
		})
	}
}

func TestForwardFailureContainmentRetriesTransientMaintenanceContention(t *testing.T) {
	var attempts int
	var stopped bool
	err := containForwardUpgradeFailure(context.Background(), forwardMaintenanceDeps{
		attach: func(ctx context.Context) (context.Context, func(), error) {
			attempts++
			if attempts < 2 {
				return nil, nil, errors.New("infrastructure_busy (lifecycle: attach)")
			}
			return ctx, func() {}, nil
		},
		stop: func(context.Context) error {
			stopped = true
			return nil
		},
	})
	if err != nil || attempts != 2 || !stopped {
		t.Fatalf("error=%v attempts=%d stopped=%t", err, attempts, stopped)
	}
}

func TestForwardFailureContainmentDoesNotRetryOwnershipErrors(t *testing.T) {
	attempts := 0
	err := containForwardUpgradeFailure(context.Background(), forwardMaintenanceDeps{
		attach: func(context.Context) (context.Context, func(), error) {
			attempts++
			return nil, nil, errors.New("lifecycle_not_owned")
		},
		stop: func(context.Context) error { return nil },
	})
	if err == nil || attempts != 1 {
		t.Fatalf("error=%v attempts=%d", err, attempts)
	}
}
