package db

import (
	"context"
	"errors"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func TestORMUserCRUDPreservesDefaultsAndMissingRows(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	repo := NewUserRepo(d)
	u, err := repo.Add(ctx, "vless", "ORM user")
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := repo.Lookup(ctx, u.UUID)
	if err != nil || !ok || !got.IsActive || got.AccountID == "" {
		t.Fatalf("defaults %+v, found=%v: %v", got, ok, err)
	}
	if err := repo.Remove(ctx, u.UUID); err != nil {
		t.Fatal(err)
	}
	renamed, err := repo.Rename(ctx, u.UUID, "renamed")
	if err != nil || renamed.Name != "renamed" || renamed.IsActive || renamed.DisabledAt == nil || renamed.AccountID != got.AccountID {
		t.Fatalf("returning disabled user %+v: %v", renamed, err)
	}
	if _, err := repo.SetPreferredExit(ctx, u.UUID, nil); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("inactive preferred-exit update: %v", err)
	}
	if err := repo.Enable(ctx, u.UUID); err != nil {
		t.Fatal(err)
	}
	updated, err := repo.SetPreferredExit(ctx, u.UUID, nil)
	if err != nil || !updated.IsActive || updated.DisabledAt != nil || updated.PreferredExitID != nil {
		t.Fatalf("NULL update %+v: %v", updated, err)
	}
	missing := uuid.NewString()
	if _, err := repo.Rename(ctx, missing, "missing"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("rename missing: %v", err)
	}
	if err := repo.Remove(ctx, missing); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("disable missing: %v", err)
	}
	if err := repo.Purge(ctx, u.UUID); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := repo.Lookup(ctx, u.UUID); err != nil || ok {
		t.Fatalf("purged lookup found=%v: %v", ok, err)
	}
}

func TestORMAdminUpsertAndNotificationDefaults(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	admins := NewBotAdminRepo(d)
	if _, err := admins.FirstAdmin(ctx); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("missing first admin: %v", err)
	}
	if err := admins.AddAdmin(ctx, 42, "initial"); err != nil {
		t.Fatal(err)
	}
	first, err := admins.FirstAdmin(ctx)
	if err != nil || first.AddedAt.IsZero() {
		t.Fatalf("admin defaults %+v: %v", first, err)
	}
	if err := admins.AddAdmin(ctx, 42, ""); err != nil {
		t.Fatal(err)
	}
	rows, err := admins.ListAdmins(ctx)
	if err != nil || len(rows) != 1 || rows[0].TelegramName != "" || !rows[0].AddedAt.Equal(first.AddedAt) {
		t.Fatalf("admin upsert %+v: %v", rows, err)
	}
	repo := NewTelegramRepo(d)
	if err := repo.EnqueueNotification(ctx, Notification{TelegramID: 42, Type: "test", Payload: map[string]any{"zero": float64(0)}}); err != nil {
		t.Fatal(err)
	}
	pending, err := repo.PendingNotifications(ctx, 1)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending %+v: %v", pending, err)
	}
	n := pending[0]
	if n.CreatedAt.IsZero() || n.SentAt != nil || n.UserUUID != nil || n.Payload["zero"] != float64(0) {
		t.Fatalf("notification defaults %+v", n)
	}
	if err := repo.MarkNotificationSent(ctx, n.ID); err != nil {
		t.Fatal(err)
	}
	pending, err = repo.PendingNotifications(ctx, 1)
	if err != nil || len(pending) != 0 {
		t.Fatalf("sent notification still pending %+v: %v", pending, err)
	}
	if err := admins.RemoveAdmin(ctx, 42); err != nil {
		t.Fatal(err)
	}
	if any, err := admins.HasAnyAdmin(ctx); err != nil || any {
		t.Fatalf("removed admin exists=%v: %v", any, err)
	}
}
