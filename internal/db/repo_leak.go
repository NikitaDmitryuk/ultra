package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

type LeakSignal struct {
	ID        int64
	UserUUID  string
	Kind      string
	Score     int
	Detail    map[string]any
	CreatedAt time.Time
}

type ConnectionBucketPoint struct {
	BucketStart time.Time
	IPs         int
}

func (r *TelegramRepo) UpsertUserIPObservation(ctx context.Context, userUUID, ip string) error {
	_, err := r.db.Pool.Exec(ctx, `
		INSERT INTO user_ip_observations(user_uuid, ip, first_seen_at, last_seen_at, sessions_seen)
		VALUES($1, $2, NOW(), NOW(), 1)
		ON CONFLICT (user_uuid, ip) DO UPDATE SET
		  last_seen_at=NOW(),
		  sessions_seen=user_ip_observations.sessions_seen+1
	`, userUUID, ip)
	return err
}

func (r *TelegramRepo) CountConcurrentIPs(ctx context.Context, userUUID string, window time.Duration) (int, error) {
	var n int
	err := r.db.Pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM user_ip_observations
		WHERE user_uuid=$1 AND last_seen_at >= NOW() - $2::interval
	`, userUUID, intervalSQL(window)).Scan(&n)
	return n, err
}

func (r *TelegramRepo) CountUniqueIPs(ctx context.Context, userUUID string, window time.Duration) (int, error) {
	var n int
	err := r.db.Pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT ip) FROM user_ip_observations
		WHERE user_uuid=$1 AND last_seen_at >= NOW() - $2::interval
	`, userUUID, intervalSQL(window)).Scan(&n)
	return n, err
}

func (r *TelegramRepo) InsertLeakSignal(ctx context.Context, userUUID, kind string, score int, detail map[string]any) error {
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	_, err = r.db.Pool.Exec(ctx, `
		INSERT INTO user_leak_signals(user_uuid, kind, score, detail)
		VALUES($1, $2, $3, $4)
	`, userUUID, kind, score, raw)
	return err
}

func (r *TelegramRepo) RecentUserLeakSignals(ctx context.Context, userUUID string, limit int) ([]LeakSignal, error) {
	rows, err := r.db.Pool.Query(ctx, `
		SELECT id, user_uuid, kind, score, detail, created_at
		FROM user_leak_signals
		WHERE user_uuid=$1
		ORDER BY created_at DESC
		LIMIT $2
	`, userUUID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LeakSignal
	for rows.Next() {
		var s LeakSignal
		var raw []byte
		if err := rows.Scan(&s.ID, &s.UserUUID, &s.Kind, &s.Score, &raw, &s.CreatedAt); err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &s.Detail)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *TelegramRepo) ConnectionsByBuckets(
	ctx context.Context,
	userUUID string,
	window time.Duration,
	bucket string,
) ([]ConnectionBucketPoint, error) {
	expr, err := bucketExpr(bucket)
	if err != nil {
		return nil, err
	}
	q := fmt.Sprintf(`
		SELECT %s AS bucket_start, COUNT(DISTINCT ip) AS ips
		FROM user_ip_observations
		WHERE user_uuid=$1 AND last_seen_at >= NOW() - $2::interval
		GROUP BY bucket_start
		ORDER BY bucket_start
	`, expr)
	rows, err := r.db.Pool.Query(ctx, q, userUUID, intervalSQL(window))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ConnectionBucketPoint
	for rows.Next() {
		var p ConnectionBucketPoint
		if err := rows.Scan(&p.BucketStart, &p.IPs); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func intervalSQL(d time.Duration) string {
	return fmt.Sprintf("%f seconds", d.Seconds())
}

func bucketExpr(bucket string) (string, error) {
	switch bucket {
	case "5m":
		return "date_trunc('hour', last_seen_at) + ((extract(minute from last_seen_at)::int / 5) * interval '5 minutes')", nil
	case "1h":
		return "date_trunc('hour', last_seen_at)", nil
	case "6h":
		return "date_trunc('day', last_seen_at) + ((extract(hour from last_seen_at)::int / 6) * interval '6 hours')", nil
	case "1d":
		return "date_trunc('day', last_seen_at)", nil
	default:
		return "", fmt.Errorf("unsupported bucket: %s", bucket)
	}
}
