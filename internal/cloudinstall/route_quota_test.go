package cloudinstall

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/google/uuid"
)

// The existing exit already has an observation when a second healthy exit is
// published between the five-minute provider polls. Exercise real quota and
// credential reads rather than granting the new location a synthetic allowance.
func TestApplyNewRouteObservesQuotaBeforeConfirmingLocation(t *testing.T) {
	for _, mode := range []string{"success", "provider_failure", "apply_failure", "missing_refresh"} {
		t.Run(mode, func(t *testing.T) {
			database := openDeleteTestDB(t)
			ctx := context.Background()
			now := time.Now().UTC()
			oldID, newID, userID := uuid.NewString(), uuid.NewString(), uuid.NewString()
			quota := db.NewQuotaRepo(database)
			for i, id := range []string{oldID, newID} {
				if _, err := database.Pool.Exec(ctx, `INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid) VALUES($1::uuid,'fixture','192.0.2.1',$2,$1::text)`, id, 440+i); err != nil {
					t.Fatal(err)
				}
				if err := quota.EnsureVultr(ctx, id, id, 1000000); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := database.Pool.Exec(ctx, `INSERT INTO users(uuid,name,telegram_id,enrollment_source) VALUES($1,'fixture',123,'invite')`, userID); err != nil {
				t.Fatal(err)
			}
			observe := func(id string) error {
				return quota.SaveBandwidth(
					ctx,
					[]db.BandwidthObservation{{ID: id, Instance: id, Monthly: 1000000, Remaining: 800000, Accrued: 1000000, Pool: true}},
					now,
				)
			}
			if err := observe(oldID); err != nil {
				t.Fatal(err)
			}
			routes := db.NewRouteRepo(database)
			if err := routes.Publish(ctx, "fixture-region", "Fixture", newID); err != nil {
				t.Fatal(err)
			}
			nodes := []exits.Node{{ID: oldID, Enabled: true}, {ID: newID, Enabled: true}}
			selected := func() string {
				t.Helper()
				if _, err := quota.Recalculate(ctx, now); err != nil {
					t.Fatal(err)
				}
				users, err := routes.Attach(ctx, []auth.User{{UUID: userID}})
				if err != nil {
					t.Fatal(err)
				}
				return auth.ExpandRoutes(users)[1].SelectExit(nodes, oldID, nil)
			}
			if got := selected(); got != oldID {
				t.Fatalf("unobserved new exit selected: %s", got)
			}
			var quotaCalls, applyCalls, refreshCalls int
			failure := errors.New("fixture failure")
			p := Provisioner{Routes: routes,
				RefreshQuota: func(context.Context) error {
					quotaCalls++
					if mode == "provider_failure" {
						return failure
					}
					return observe(newID)
				},
				Apply: func(context.Context) error {
					applyCalls++
					if got := selected(); got != newID {
						t.Fatalf("confirmed route still falls back: %s", got)
					}
					if mode == "apply_failure" {
						return failure
					}
					return nil
				},
				Refresh: func(context.Context) error { refreshCalls++; return nil },
			}
			if mode == "missing_refresh" {
				p.RefreshQuota = nil
			}
			err := p.ApplyRoute(ctx, &cloud.Operation{ExitID: newID})
			applied, readErr := routes.IsApplied(ctx, newID)
			if readErr != nil || applied != (mode == "success") || (err == nil) != applied {
				t.Fatalf("receipt applied=%v err=%v read=%v", applied, err, readErr)
			}
			if mode != "success" {
				if refreshCalls != 0 || ((mode == "provider_failure" || mode == "missing_refresh") && applyCalls != 0) {
					t.Fatalf("failure advanced apply=%d refresh=%d", applyCalls, refreshCalls)
				}
				return
			}
			// A committed receipt survives a lost response. Retrying must refresh
			// users without requiring a second provider request or runtime apply.
			p.RefreshQuota = func(context.Context) error { t.Fatal("repeated quota request"); return failure }
			if err = p.ApplyRoute(ctx, &cloud.Operation{ExitID: newID}); err != nil || quotaCalls != 1 || applyCalls != 1 ||
				refreshCalls != 2 {
				t.Fatalf("retry: err=%v quota=%d apply=%d refresh=%d", err, quotaCalls, applyCalls, refreshCalls)
			}
		})
	}
}
