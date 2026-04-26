package db

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/google/uuid"
)

// TestUserRepoPurgeCascades guards the contract that DELETE FROM users wipes
// all referencing rows via ON DELETE CASCADE — that is the whole reason we can
// implement hard delete with a single statement.
func TestUserRepoPurgeCascades(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	database, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(database.Close)

	userUUID := uuid.NewString()
	_, err = database.Pool.Exec(ctx, `INSERT INTO users(uuid, name) VALUES($1, $2)`, userUUID, "purge-test")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = database.Pool.Exec(context.Background(), `DELETE FROM users WHERE uuid=$1`, userUUID)
	})

	if _, err = database.Pool.Exec(ctx, `
		INSERT INTO user_ip_observations(user_uuid, ip, first_seen_at, last_seen_at, sessions_seen)
		VALUES($1, '203.0.113.5'::inet, NOW(), NOW(), 1)
	`, userUUID); err != nil {
		t.Fatalf("insert observation: %v", err)
	}
	if _, err = database.Pool.Exec(ctx, `
		INSERT INTO user_leak_signals(user_uuid, kind, score, detail, created_at)
		VALUES($1, 'concurrent_ips', 1, '{}'::jsonb, NOW())
	`, userUUID); err != nil {
		t.Fatalf("insert leak signal: %v", err)
	}
	if _, err = database.Pool.Exec(ctx, `
		INSERT INTO traffic_stats(user_uuid, collected_at, uplink_bytes, downlink_bytes)
		VALUES($1, NOW(), 100, 200)
	`, userUUID); err != nil {
		t.Fatalf("insert traffic_stats: %v", err)
	}
	if _, err = database.Pool.Exec(ctx, `
		INSERT INTO monthly_traffic(user_uuid, year, month, uplink_bytes, downlink_bytes)
		VALUES($1, 2026, 4, 1, 2)
	`, userUUID); err != nil {
		t.Fatalf("insert monthly_traffic: %v", err)
	}
	if _, err = database.Pool.Exec(ctx, `
		INSERT INTO notifications(user_uuid, telegram_id, type, payload, sent_at, created_at)
		VALUES($1, 999001, 'purge_test', '{}'::jsonb, NOW(), NOW())
	`, userUUID); err != nil {
		t.Fatalf("insert notification: %v", err)
	}

	repo := NewUserRepo(database)
	if err := repo.Purge(ctx, userUUID); err != nil {
		t.Fatalf("Purge: %v", err)
	}

	checks := []struct {
		table  string
		column string
	}{
		{"users", "uuid"},
		{"user_ip_observations", "user_uuid"},
		{"user_leak_signals", "user_uuid"},
		{"traffic_stats", "user_uuid"},
		{"monthly_traffic", "user_uuid"},
		{"notifications", "user_uuid"},
	}
	for _, c := range checks {
		var n int
		query := "SELECT COUNT(*) FROM " + c.table + " WHERE " + c.column + "=$1"
		if err := database.Pool.QueryRow(ctx, query, userUUID).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", c.table, err)
		}
		if n != 0 {
			t.Fatalf("%s: expected 0 rows after Purge, got %d", c.table, n)
		}
	}

	// Second Purge call must report ErrUserNotFound (not a silent success).
	if err := repo.Purge(ctx, userUUID); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound on missing user, got %v", err)
	}
}

func TestUserRepoAddSocks5User(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	database, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(database.Close)

	repo := NewUserRepo(database)
	repo.SetSOCKS5BridgePorts(10810, 10899, 1080)

	u, err := repo.Add(ctx, "socks5", "socks-repo-test")
	if err != nil {
		t.Fatalf("Add socks5: %v", err)
	}
	if u.Kind != "socks5" || u.SocksUsername == "" || u.SocksPassword == "" || u.SocksPort == nil {
		t.Fatalf("unexpected user: %#v", u)
	}
	t.Cleanup(func() {
		_, _ = database.Pool.Exec(context.Background(), `DELETE FROM users WHERE uuid=$1`, u.UUID)
	})

	if _, err := repo.RotateSocksPassword(ctx, u.UUID); err != nil {
		t.Fatalf("RotateSocksPassword: %v", err)
	}
	if err := repo.Purge(ctx, u.UUID); err != nil {
		t.Fatalf("Purge: %v", err)
	}
}
