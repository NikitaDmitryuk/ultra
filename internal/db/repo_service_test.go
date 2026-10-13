package db

import (
	"context"
	"encoding/base64"
	"github.com/NikitaDmitryuk/ultra/internal/subscriptionkey"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestMonitorIdentityAndQuotaSurviveRecreation(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	repo := NewUserRepo(d)
	targets := []string{"https://probe.example/health"}
	first, e := repo.EnsureMonitorAccess(ctx, targets)
	if e != nil {
		t.Fatal(e)
	}
	again, e := repo.EnsureMonitorAccess(ctx, targets)
	if e != nil || first.UUID != again.UUID || first.AccountID != again.AccountID {
		t.Fatal("identity changed", e)
	}
	rotated, e := repo.RotateUUID(ctx, first.UUID)
	if e != nil {
		t.Fatal(e)
	}
	rotatedUser, e := repo.EnsureMonitorAccess(ctx, targets)
	if e != nil || rotatedUser.UUID != rotated || rotatedUser.AccountID != first.AccountID {
		t.Fatal("rotation lost service owner", e)
	}
	first.UUID = rotated
	exit := uuid.NewString()
	now := time.Now().UTC()
	_, e = d.Pool.Exec(ctx, `INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid) VALUES($1,'fixture','127.0.0.1',12001,$2)`, exit, uuid.NewString())
	if e != nil {
		t.Fatal(e)
	}
	_, e = d.Pool.Exec(ctx, `INSERT INTO exit_traffic_budgets(exit_id,monthly_bytes,source,is_fallback) VALUES($1,32000000000000,'manual',true)`, exit)
	if e != nil {
		t.Fatal(e)
	}
	_, e = d.Pool.Exec(ctx, `INSERT INTO account_exit_usage(account_id,exit_id,period,charged_bytes) VALUES($1,$2,$3,5368709120)`, first.AccountID, exit, now.Format("2006-01"))
	if e != nil {
		t.Fatal(e)
	}
	_, e = d.Pool.Exec(ctx, `DELETE FROM users WHERE uuid=$1`, first.UUID)
	if e != nil {
		t.Fatal(e)
	}
	next, e := repo.EnsureMonitorAccess(ctx, targets)
	if e != nil || next.UUID == first.UUID || next.AccountID != first.AccountID {
		t.Fatal("owner recreated", e)
	}
	quota := NewQuotaRepo(d)
	if _, e = quota.Recalculate(ctx, now); e != nil {
		t.Fatal(e)
	}
	var blocked bool
	var reason string
	var used, limit int64
	e = d.Pool.QueryRow(ctx, `SELECT blocked,reason,used_bytes,limit_bytes FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2`, next.UUID, exit).Scan(&blocked, &reason, &used, &limit)
	if e != nil || !blocked || reason != "monitor_quota_exhausted" || used != 5368709120 || limit != 5368709120 {
		t.Fatalf("quota returned: blocked=%v reason=%s used=%d limit=%d err=%v", blocked, reason, used, limit, e)
	}
	// A normal monthly boundary can renew the fixed monthly allowance.
	if _, e = quota.Recalculate(ctx, now.AddDate(0, 1, 0)); e != nil {
		t.Fatal(e)
	}
	e = d.Pool.QueryRow(ctx, `SELECT limit_bytes FROM user_exit_quotas WHERE user_uuid=$1 AND exit_id=$2`, next.UUID, exit).Scan(&limit)
	if e != nil || limit != 5368709120 {
		t.Fatal("monthly allowance", limit, e)
	}
	users, e := repo.ListAll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, u := range users {
		if u.UUID == next.UUID {
			found = len(u.ServiceTargets) == 1
		}
	}
	if !found {
		t.Fatal("runtime lost service restrictions")
	}
}
func TestInitialMonitorAdminNeverReassignsOwner(t *testing.T) {
	d := openTestDB(t)
	r := NewUserRepo(d)
	ctx := context.Background()
	if e := r.EnsureInitialMonitorAdmin(ctx, 1234); e != nil {
		t.Fatal(e)
	}
	if e := r.EnsureInitialMonitorAdmin(ctx, 1234); e != nil {
		t.Fatal(e)
	}
	if e := r.EnsureInitialMonitorAdmin(ctx, 5678); e == nil {
		t.Fatal("ownership changed")
	}
}

func TestMonitorCannotObtainPublicSubscription(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	u, e := NewUserRepo(d).EnsureMonitorAccess(ctx, []string{"https://probe.example/health"})
	if e != nil {
		t.Fatal(e)
	}
	r := NewSubscriptionRepo(d, &subscriptionkey.Ring{Active: "v1", Keys: map[string]string{"v1": base64.StdEncoding.EncodeToString(make([]byte, 32))}})
	if _, e = r.Rotate(ctx, u.UUID); e == nil {
		t.Fatal("service received public subscription")
	}
}
