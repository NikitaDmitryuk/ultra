package db

import (
	"context"
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/quota"
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
	if la <= lb {
		t.Fatal("equal allocation despite different demand")
	}
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
