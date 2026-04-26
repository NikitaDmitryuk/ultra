package db

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPruneMonitoringRetention(t *testing.T) {
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
	tg := time.Now().UnixNano()
	repo := NewTelegramRepo(database)

	_, err = database.Pool.Exec(ctx, `INSERT INTO users(uuid, name) VALUES($1, $2)`, userUUID, "maintenance-test")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = database.Pool.Exec(context.Background(), `DELETE FROM users WHERE uuid=$1`, userUUID)
	})

	oldSent := fmt.Sprintf(`{"hello":"world-%d"}`, tg)
	_, err = database.Pool.Exec(ctx, `
		INSERT INTO notifications(user_uuid, telegram_id, type, payload, sent_at, created_at)
		VALUES($1, $2, 'test', $3::jsonb, NOW() - INTERVAL '40 days', NOW() - INTERVAL '40 days')
	`, userUUID, tg, oldSent)
	if err != nil {
		t.Fatalf("insert old notification: %v", err)
	}

	_, err = database.Pool.Exec(ctx, `
		INSERT INTO notifications(user_uuid, telegram_id, type, payload, sent_at, created_at)
		VALUES($1, $2, 'test', '{}'::jsonb, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day')
	`, userUUID, tg+1)
	if err != nil {
		t.Fatalf("insert recent notification: %v", err)
	}

	_, err = database.Pool.Exec(ctx, `
		INSERT INTO user_ip_observations(user_uuid, ip, first_seen_at, last_seen_at, sessions_seen)
		VALUES($1, '198.51.100.10'::inet, NOW() - INTERVAL '40 days', NOW() - INTERVAL '40 days', 1)
	`, userUUID)
	if err != nil {
		t.Fatalf("insert old observation: %v", err)
	}

	_, err = database.Pool.Exec(ctx, `
		INSERT INTO user_ip_observations(user_uuid, ip, first_seen_at, last_seen_at, sessions_seen)
		VALUES($1, '198.51.100.11'::inet, NOW() - INTERVAL '1 day', NOW() - INTERVAL '1 day', 1)
	`, userUUID)
	if err != nil {
		t.Fatalf("insert recent observation: %v", err)
	}

	_, err = database.Pool.Exec(ctx, `
		INSERT INTO user_leak_signals(user_uuid, kind, score, detail, created_at)
		VALUES($1, 'x', 1, '{}'::jsonb, NOW() - INTERVAL '40 days')
	`, userUUID)
	if err != nil {
		t.Fatalf("insert old signal: %v", err)
	}

	_, err = database.Pool.Exec(ctx, `
		INSERT INTO user_leak_signals(user_uuid, kind, score, detail, created_at)
		VALUES($1, 'y', 1, '{}'::jsonb, NOW() - INTERVAL '1 day')
	`, userUUID)
	if err != nil {
		t.Fatalf("insert recent signal: %v", err)
	}

	n, o, s, err := repo.PruneMonitoringRetention(ctx)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if n < 1 || o < 1 || s < 1 {
		t.Fatalf("expected deletes for each category, got notifications=%d observations=%d signals=%d", n, o, s)
	}

	var notifCount, obsCount, sigCount int
	_ = database.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM notifications WHERE telegram_id=$1`, tg).Scan(&notifCount)
	_ = database.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM user_ip_observations WHERE user_uuid=$1 AND host(ip)='198.51.100.10'`, userUUID).
		Scan(&obsCount)
	_ = database.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM user_leak_signals WHERE user_uuid=$1 AND kind='x'`, userUUID).Scan(&sigCount)
	if notifCount != 0 || obsCount != 0 || sigCount != 0 {
		t.Fatalf("old rows still present: notifications=%d observations=%d signals=%d", notifCount, obsCount, sigCount)
	}

	var recentNotif, recentObs, recentSig int
	_ = database.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM notifications WHERE telegram_id=$1`, tg+1).Scan(&recentNotif)
	_ = database.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM user_ip_observations WHERE user_uuid=$1 AND host(ip)='198.51.100.11'`, userUUID).
		Scan(&recentObs)
	_ = database.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM user_leak_signals WHERE user_uuid=$1 AND kind='y'`, userUUID).Scan(&recentSig)
	if recentNotif != 1 || recentObs != 1 || recentSig != 1 {
		t.Fatalf("recent rows pruned unexpectedly: notifications=%d observations=%d signals=%d", recentNotif, recentObs, recentSig)
	}
}
