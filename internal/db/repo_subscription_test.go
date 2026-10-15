package db

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/subscriptionkey"
)

func TestSubscriptionLifecycle(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	users := NewUserRepo(d)
	user, err := users.Add(ctx, "vless", "subscription-test")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = users.Purge(ctx, user.UUID) })
	repo := NewSubscriptionRepo(
		d,
		&subscriptionkey.Ring{Active: "v1", Keys: map[string]string{"v1": base64.StdEncoding.EncodeToString(make([]byte, 32))}},
	)
	token, err := repo.Rotate(ctx, user.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if id, err := repo.Resolve(ctx, token); err != nil || id != user.UUID {
		t.Fatalf("resolve: %s %v", id, err)
	}
	var stored []byte
	if err := d.Pool.QueryRow(ctx, `SELECT token_hash FROM subscription_tokens WHERE user_uuid=$1`, user.UUID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(token))
	if string(stored) != string(digest[:]) {
		t.Fatal("not a digest")
	}
	next, err := repo.Rotate(ctx, user.UUID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Resolve(ctx, token); err == nil {
		t.Fatal("old token valid")
	}
	if err := users.Remove(ctx, user.UUID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Resolve(ctx, next); err == nil {
		t.Fatal("disabled user resolved")
	}
	if err := users.Enable(ctx, user.UUID); err != nil {
		t.Fatal(err)
	}
	if err := repo.Revoke(ctx, user.UUID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Resolve(ctx, next); err == nil {
		t.Fatal("revoked token resolved")
	}
	if _, err := repo.Resolve(ctx, "invalid"); err == nil {
		t.Fatal("invalid token resolved")
	}
}

func TestSubscriptionAdminOwner(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	users := NewUserRepo(d)
	u, err := users.Add(ctx, "vless", "admin-owner")
	if err != nil {
		t.Fatal(err)
	}
	repo := NewSubscriptionRepo(d)
	allowed, err := repo.IsAdminOwner(ctx, u.UUID)
	if err != nil || allowed {
		t.Fatal("unlinked owner", allowed, err)
	}
	if _, err = d.Pool.Exec(ctx, `UPDATE users SET telegram_id=12345 WHERE uuid=$1`, u.UUID); err != nil {
		t.Fatal(err)
	}
	admin := NewBotAdminRepo(d)
	if err = admin.AddAdmin(ctx, 12345, "test"); err != nil {
		t.Fatal(err)
	}
	allowed, err = repo.IsAdminOwner(ctx, u.UUID)
	if err != nil || !allowed {
		t.Fatal("admin owner", allowed, err)
	}
	if err = admin.RemoveAdmin(ctx, 12345); err != nil {
		t.Fatal(err)
	}
	allowed, err = repo.IsAdminOwner(ctx, u.UUID)
	if err != nil || allowed {
		t.Fatal("removed admin", allowed, err)
	}
}

func TestIngressNoticeDeduplicates(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	users := NewUserRepo(d)
	u, err := users.Add(ctx, "vless", "notice-owner")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.Pool.Exec(ctx, `UPDATE users SET telegram_id=12345 WHERE uuid=$1`, u.UUID); err != nil {
		t.Fatal(err)
	}
	repo := NewSubscriptionRepo(
		d,
		&subscriptionkey.Ring{Active: "v1", Keys: map[string]string{"v1": base64.StdEncoding.EncodeToString(make([]byte, 32))}},
	)
	if _, err = repo.Rotate(ctx, u.UUID); err != nil {
		t.Fatal(err)
	}
	n, err := repo.EnqueueIngressNotice(ctx, "test-release", "Update your existing subscription")
	if err != nil || n != 1 {
		t.Fatal("first notice", n, err)
	}
	n, err = repo.EnqueueIngressNotice(ctx, "test-release", "Update your existing subscription")
	if err != nil || n != 0 {
		t.Fatal("duplicate notice", n, err)
	}
}
