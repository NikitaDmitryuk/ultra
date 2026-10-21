package db

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
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

func TestSubscriptionGetOrReissueIsStableAndSerializesKeyRecovery(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	users := NewUserRepo(d)
	user, err := users.Add(ctx, "vless", "subscription-recovery")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = users.Purge(ctx, user.UUID) })
	keyA := &subscriptionkey.Ring{Active: "v1", Keys: map[string]string{"v1": base64.StdEncoding.EncodeToString(make([]byte, 32))}}
	keyB := &subscriptionkey.Ring{Active: "v1", Keys: map[string]string{"v1": base64.StdEncoding.EncodeToString(bytesOf(1, 32))}}
	oldRepo := NewSubscriptionRepo(d, keyA)
	oldToken, err := oldRepo.GetOrCreate(ctx, user.UUID)
	if err != nil {
		t.Fatal(err)
	}
	validToken, rotated, err := oldRepo.GetOrReissue(ctx, user.UUID)
	if err != nil || rotated || validToken != oldToken {
		t.Fatalf("valid link was not reused: token=%q rotated=%v err=%v", validToken, rotated, err)
	}
	if _, rotated, err := oldRepo.GetOrReissue(ctx, "00000000-0000-4000-8000-000000000000"); err == nil || rotated {
		t.Fatalf("missing member unexpectedly rotated: rotated=%v err=%v", rotated, err)
	}
	missingRing := NewSubscriptionRepo(d)
	if _, rotated, err := missingRing.GetOrReissue(ctx, user.UUID); !errors.Is(err, subscriptionkey.ErrUnavailable) || rotated {
		t.Fatalf("missing key ring: rotated=%v err=%v", rotated, err)
	}
	newRepo := NewSubscriptionRepo(d, keyB)
	const n = 8
	tokens := make([]string, n)
	rotations := make([]bool, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range tokens {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tokens[i], rotations[i], errs[i] = newRepo.GetOrReissue(ctx, user.UUID)
		}(i)
	}
	wg.Wait()
	first := tokens[0]
	if first == "" || first == oldToken {
		t.Fatalf("expected replacement token, got %q", first)
	}
	rotatedCount := 0
	for i := range tokens {
		if errs[i] != nil || tokens[i] != first {
			t.Fatalf("concurrent request %d returned token=%q err=%v, want %q", i, tokens[i], errs[i], first)
		}
		if rotations[i] {
			rotatedCount++
		}
	}
	if rotatedCount != 1 {
		t.Fatalf("rotated=%d times, want exactly once", rotatedCount)
	}
	if _, rotated, err := newRepo.GetOrReissue(ctx, user.UUID); err != nil || rotated {
		t.Fatalf("stable follow-up: rotated=%v err=%v", rotated, err)
	}
	if id, err := newRepo.Resolve(ctx, first); err != nil || id != user.UUID {
		t.Fatalf("new token does not resolve: id=%q err=%v", id, err)
	}
}

func bytesOf(value byte, n int) []byte {
	result := make([]byte, n)
	for i := range result {
		result[i] = value
	}
	return result
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
