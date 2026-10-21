package db

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestStaticBudgetInitializationPreservesUsageAndRejectsChanges(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	id := uuid.NewString()
	if _, err := d.Pool.Exec(ctx, `INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid) VALUES($1,'fixture','198.18.0.11',24443,$2)`, id, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	r := NewQuotaRepo(d)
	nodes := []StaticBudgetNode{{Address: "198.18.0.11"}}
	if err := r.EnsureStaticBudgets(ctx, nodes); err == nil {
		t.Fatal("missing budget accepted")
	}
	nodes[0].Budget = &StaticBudget{MonthlyBytes: 100 << 30, Fallback: true}
	if err := r.EnsureStaticBudgets(ctx, nodes); err != nil {
		t.Fatal(err)
	}
	monitor, err := NewUserRepo(d).EnsureMonitorAccess(ctx, []string{"https://probe.example/health"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Recalculate(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	var limit int64
	var blocked bool
	if err = d.Pool.QueryRow(ctx, `SELECT limit_bytes,blocked FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2`, monitor.UUID, id).Scan(&limit, &blocked); err != nil ||
		blocked ||
		limit != 5<<30 {
		t.Fatal("fresh monitor not provisioned", limit, blocked, err)
	}
	owner := uuid.NewString()
	if _, err := d.Pool.Exec(ctx, `INSERT INTO traffic_accounts(account_id) VALUES($1)`, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool.Exec(ctx, `INSERT INTO account_exit_usage(account_id,exit_id,period,charged_bytes) VALUES($1,$2,'2026-10',123456)`, owner, id); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Pool.Exec(ctx, `UPDATE exit_traffic_budgets SET provider_used_bytes=42,provider_error='preserve' WHERE exit_id=$1`, id); err != nil {
		t.Fatal(err)
	}
	if err := r.EnsureStaticBudgets(ctx, nodes); err != nil {
		t.Fatal(err)
	}
	nodes[0].Budget.MonthlyBytes++
	if err := r.EnsureStaticBudgets(ctx, nodes); err == nil {
		t.Fatal("budget silently increased")
	}
	nodes[0].Budget = nil
	if err := r.EnsureStaticBudgets(ctx, nodes); err != nil {
		t.Fatal(err)
	}
	var used, observed, monthly int64
	var code string
	if err := d.Pool.QueryRow(ctx, `SELECT charged_bytes FROM account_exit_usage WHERE account_id=$1`, owner).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if err := d.Pool.QueryRow(ctx, `SELECT provider_used_bytes,provider_error,monthly_bytes FROM exit_traffic_budgets WHERE exit_id=$1`, id).Scan(&observed, &code, &monthly); err != nil {
		t.Fatal(err)
	}
	if used != 123456 || observed != 42 || code != "preserve" || monthly != 100<<30 {
		t.Fatalf("state changed: %d %d %q %d", used, observed, code, monthly)
	}
}

func TestStaticBudgetBatchRollsBackOnUnknownExit(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	id := uuid.NewString()
	if _, err := d.Pool.Exec(ctx, `INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid) VALUES($1,'fixture','198.18.0.11',24443,$2)`, id, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	nodes := []StaticBudgetNode{
		{Address: "198.18.0.11", Budget: &StaticBudget{MonthlyBytes: 100 << 30}},
		{Address: "198.18.0.12", Budget: &StaticBudget{MonthlyBytes: 100 << 30}},
	}
	if err := NewQuotaRepo(d).EnsureStaticBudgets(ctx, nodes); err == nil {
		t.Fatal("unknown exit accepted")
	}
	var count int
	if err := d.Pool.QueryRow(ctx, `SELECT count(*) FROM exit_traffic_budgets`).Scan(&count); err != nil || count != 0 {
		t.Fatal("partial transaction committed", count, err)
	}
}
