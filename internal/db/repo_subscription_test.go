package db

import (
	"context"
	"crypto/sha256"
	"testing"
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
	repo := NewSubscriptionRepo(d)
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
