package db

import (
	"context"
	"encoding/json"
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/quota"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestQuotaDemandFallbackAndRecovery(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	repo := NewQuotaRepo(d)
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	ams := "10000000-0000-0000-0000-000000000001"
	fra := "10000000-0000-0000-0000-000000000002"
	a := "20000000-0000-0000-0000-000000000001"
	b := "20000000-0000-0000-0000-000000000002"
	for i, id := range []string{ams, fra} {
		_, e := d.Pool.Exec(ctx, `INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid) VALUES($1,$2,'127.0.0.1',$3,$4)`, id, id, 10000+i, id)
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, id := range []string{a, b} {
		_, e := d.Pool.Exec(ctx, `INSERT INTO users(uuid,name) VALUES($1,'test')`, id)
		if e != nil {
			t.Fatal(e)
		}
	}
	if e := repo.EnsureVultr(ctx, fra, "fixture", 1000*quota.GiB); e != nil {
		t.Fatal(e)
	}
	_, e := d.Pool.Exec(ctx, `INSERT INTO exit_traffic_budgets(exit_id,monthly_bytes,source,is_fallback) VALUES($1,32000000000000,'manual',true)`, ams)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.Recalculate(ctx, now); e != nil {
		t.Fatal(e)
	}
	var blocked bool
	check := func(want bool) {
		t.Helper()
		if e = d.Pool.QueryRow(ctx, `SELECT blocked FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2`, a, fra).Scan(&blocked); e != nil || blocked != want {
			t.Fatal("blocked", blocked, e)
		}
	}
	check(true)
	if e = repo.Observe(ctx, fra, 0, 1000*quota.GiB, "", now); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.Recalculate(ctx, now); e != nil {
		t.Fatal(e)
	}
	check(false)
	_, e = d.Pool.Exec(ctx, `INSERT INTO daily_route_traffic(user_uuid,day,exit_tag,uplink_bytes,downlink_bytes) VALUES($1,$2,$3,0,$4)`, a, now.AddDate(0, 0, -1).Format("2006-01-02"), "to-exit-"+fra, 100*quota.GiB)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.Recalculate(ctx, now); e != nil {
		t.Fatal(e)
	}
	var la, lb int64
	if e = d.Pool.QueryRow(ctx, `SELECT limit_bytes FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2`, a, fra).Scan(&la); e != nil {
		t.Fatal(e)
	}
	if e = d.Pool.QueryRow(ctx, `SELECT limit_bytes FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2`, b, fra).Scan(&lb); e != nil {
		t.Fatal(e)
	}
	if la != lb || la != 200*quota.GiB {
		t.Fatal("monthly ceilings depend on daily demand", la, lb)
	}
	snapshot, e := repo.Snapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	// Exhaust the user's monthly quarter, including yesterday's traffic.
	_, e = d.Pool.Exec(ctx, `UPDATE daily_route_traffic SET downlink_bytes=$2 WHERE user_uuid=$1`, a, 200*quota.GiB)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.Recalculate(ctx, now); e != nil {
		t.Fatal(e)
	}
	check(true)
	if e = repo.Acknowledge(ctx, snapshot); e != nil {
		t.Fatal(e)
	}
	var applied bool
	if e = d.Pool.QueryRow(ctx, `SELECT applied FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2`, a, fra).Scan(&applied); e != nil || applied {
		t.Fatal("acknowledged a newer calculation", e)
	}
	if e = repo.Observe(ctx, fra, 0, 1000*quota.GiB, "", now.AddDate(0, 0, 1)); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.Recalculate(ctx, now.AddDate(0, 0, 1)); e != nil {
		t.Fatal(e)
	}
	check(true)
	rotated, err := NewUserRepo(d).RotateUUID(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	a = rotated
	check(true)
	var usedAfterRotation int64
	if e = d.Pool.QueryRow(ctx, `SELECT used_bytes FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2`, a, fra).Scan(&usedAfterRotation); e != nil || usedAfterRotation != 200*quota.GiB {
		t.Fatal("rotation reset usage", e)
	}
	nextMonth := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	if e = repo.Observe(ctx, fra, 0, 1000*quota.GiB, "", nextMonth); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.Recalculate(ctx, nextMonth); e != nil {
		t.Fatal(e)
	}
	check(false)

	if e = repo.Observe(ctx, fra, 0, 0, "", now); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.Recalculate(ctx, now); e != nil {
		t.Fatal(e)
	}
	check(true)
	users, e := NewRouteRepo(d).Attach(ctx, []auth.User{{UUID: a}})
	if e != nil || users[0].FallbackExitID != ams || len(users[0].ExcludedExitIDs) != 1 {
		t.Fatal("quota cache not attached", e)
	}
	if e = repo.Observe(ctx, fra, 0, 1000*quota.GiB, "", now); e != nil {
		t.Fatal(e)
	}
	if _, e = repo.Recalculate(ctx, now.AddDate(0, 0, 1)); e != nil {
		t.Fatal(e)
	}
	check(true) // stale provider data
	_, e = d.Pool.Exec(ctx, `UPDATE exit_nodes SET enabled=false WHERE id=$1`, fra)
	if e != nil {
		t.Fatal(e)
	}
	budgets, e := repo.Budgets(ctx)
	if e != nil {
		t.Fatal(e)
	}
	for _, budget := range budgets {
		if budget.ID == fra && budget.Enabled {
			t.Fatal("disabled paid resource treated as routing capacity")
		}
	}

}

func TestBudgetPlanMatchesReadyInstanceAndExit(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	id := uuid.NewString()
	if _, err := d.Pool.Exec(ctx, `INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid) VALUES($1,'plan-test','127.0.0.1',51001,$2)`, id, id); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Pool.Exec(ctx, `DELETE FROM exit_nodes WHERE id=$1`, id) })
	repo := NewQuotaRepo(d)
	if err := repo.EnsureVultr(ctx, id, "plan-instance", 1); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, state, instance, exit, plan string
		want                              bool
	}{
		{"ready", "ready", "plan-instance", id, "correct", true},
		{"other instance", "ready", "other", id, "wrong", false},
		{"other exit", "ready", "plan-instance", uuid.NewString(), "wrong", false},
		{"incomplete", "installing", "plan-instance", id, "wrong", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opID := uuid.NewString()
			op := cloud.Operation{ID: opID, State: tt.state, InstanceID: tt.instance, ExitID: tt.exit, Offer: cloud.Offer{Plan: cloud.Plan{ID: tt.plan, Bandwidth: 1024}}}
			body, err := json.Marshal(op)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = d.Pool.Exec(ctx, `INSERT INTO cloud_offers(id,actor,expires_at,body) VALUES($1,1,NOW(),'{}')`, opID); err != nil {
				t.Fatal(err)
			}
			defer func() {
				_, _ = d.Pool.Exec(ctx, `DELETE FROM cloud_operations WHERE id=$1`, opID)
				_, _ = d.Pool.Exec(ctx, `DELETE FROM cloud_offers WHERE id=$1`, opID)
			}()
			if _, err = d.Pool.Exec(ctx, `INSERT INTO cloud_operations(id,state,body) VALUES($1,$2,$3)`, opID, tt.state, body); err != nil {
				t.Fatal(err)
			}
			budgets, err := repo.Budgets(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, b := range budgets {
				if b.ID == id {
					if tt.want {
						if b.PlanID != "correct" || b.PlanBandwidth != 1024 {
							t.Fatalf("saved plan missing: %+v", b)
						}
					} else if b.PlanID != "" || b.PlanBandwidth != 0 {
						t.Fatalf("unrelated plan accepted: %+v", b)
					}
					encoded, err := json.Marshal(b)
					if err != nil {
						t.Fatal(err)
					}
					var public map[string]any
					if err = json.Unmarshal(encoded, &public); err != nil {
						t.Fatal(err)
					}
					if len(public) != 10 {
						t.Fatalf("public budget changed: %s", encoded)
					}
					return
				}
			}
			t.Fatal("budget missing")
		})
	}
}
