package db

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db/sqlc"
	"github.com/jackc/pgx/v5/pgtype"
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
	pgUUID, err := toPGUUID(userUUID)
	if err != nil {
		return err
	}
	addr, err := parseIPAddr(ip)
	if err != nil {
		return err
	}
	return r.db.Queries.UpsertUserIPObservation(ctx, sqlc.UpsertUserIPObservationParams{UserUuid: pgUUID, Ip: addr})
}

func (r *TelegramRepo) CountConcurrentIPs(ctx context.Context, userUUID string, window time.Duration) (int, error) {
	pgUUID, err := toPGUUID(userUUID)
	if err != nil {
		return 0, err
	}
	n, err := r.db.Queries.CountConcurrentIPs(ctx, sqlc.CountConcurrentIPsParams{UserUuid: pgUUID, Column2: toPGInterval(window)})
	return int(n), err
}

func (r *TelegramRepo) CountUniqueIPs(ctx context.Context, userUUID string, window time.Duration) (int, error) {
	pgUUID, err := toPGUUID(userUUID)
	if err != nil {
		return 0, err
	}
	n, err := r.db.Queries.CountUniqueIPs(ctx, sqlc.CountUniqueIPsParams{UserUuid: pgUUID, Column2: toPGInterval(window)})
	return int(n), err
}

func (r *TelegramRepo) InsertLeakSignal(ctx context.Context, userUUID, kind string, score int, detail map[string]any) error {
	raw, err := json.Marshal(detail)
	if err != nil {
		return err
	}
	pgUUID, err := toPGUUID(userUUID)
	if err != nil {
		return err
	}
	return r.db.Queries.InsertLeakSignal(ctx, sqlc.InsertLeakSignalParams{UserUuid: pgUUID, Kind: kind, Score: int32(score), Detail: raw})
}

func (r *TelegramRepo) RecentUserLeakSignals(ctx context.Context, userUUID string, limit int) ([]LeakSignal, error) {
	pgUUID, err := toPGUUID(userUUID)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.Queries.RecentUserLeakSignals(ctx, sqlc.RecentUserLeakSignalsParams{UserUuid: pgUUID, Limit: int32(limit)})
	if err != nil {
		return nil, err
	}
	out := make([]LeakSignal, 0, len(rows))
	for _, row := range rows {
		s := LeakSignal{
			ID:        row.ID,
			UserUUID:  fromPGUUID(row.UserUuid),
			Kind:      row.Kind,
			Score:     int(row.Score),
			CreatedAt: timeFromPG(row.CreatedAt),
		}
		if len(row.Detail) > 0 {
			_ = json.Unmarshal(row.Detail, &s.Detail)
		}
		out = append(out, s)
	}
	return out, nil
}

func (r *TelegramRepo) ConnectionsByBuckets(
	ctx context.Context,
	userUUID string,
	window time.Duration,
	bucket string,
) ([]ConnectionBucketPoint, error) {
	pgUUID, err := toPGUUID(userUUID)
	if err != nil {
		return nil, err
	}
	interval := toPGInterval(window)
	var queryErr error
	var out []ConnectionBucketPoint
	switch bucket {
	case "5m":
		var rows []sqlc.ConnectionsByBuckets5mRow
		rows, queryErr = r.db.Queries.ConnectionsByBuckets5m(ctx, sqlc.ConnectionsByBuckets5mParams{UserUuid: pgUUID, Column2: interval})
		out = connectionBucketsFrom5m(rows)
	case "1h":
		var rows []sqlc.ConnectionsByBuckets1hRow
		rows, queryErr = r.db.Queries.ConnectionsByBuckets1h(ctx, sqlc.ConnectionsByBuckets1hParams{UserUuid: pgUUID, Column2: interval})
		out = connectionBucketsFrom1h(rows)
	case "6h":
		var rows []sqlc.ConnectionsByBuckets6hRow
		rows, queryErr = r.db.Queries.ConnectionsByBuckets6h(ctx, sqlc.ConnectionsByBuckets6hParams{UserUuid: pgUUID, Column2: interval})
		out = connectionBucketsFrom6h(rows)
	case "1d":
		var rows []sqlc.ConnectionsByBuckets1dRow
		rows, queryErr = r.db.Queries.ConnectionsByBuckets1d(ctx, sqlc.ConnectionsByBuckets1dParams{UserUuid: pgUUID, Column2: interval})
		out = connectionBucketsFrom1d(rows)
	default:
		return nil, fmt.Errorf("unsupported bucket: %s", bucket)
	}
	if queryErr != nil {
		return nil, queryErr
	}
	return out, nil
}

func intervalSQL(d time.Duration) string {
	return fmt.Sprintf("%f seconds", d.Seconds())
}

func connectionBucketPoint(bucketStart pgtype.Timestamptz, ips int32) ConnectionBucketPoint {
	return ConnectionBucketPoint{BucketStart: timeFromPG(bucketStart), IPs: int(ips)}
}

func connectionBucketsFrom5m(rows []sqlc.ConnectionsByBuckets5mRow) []ConnectionBucketPoint {
	out := make([]ConnectionBucketPoint, 0, len(rows))
	for _, row := range rows {
		out = append(out, connectionBucketPoint(row.BucketStart, row.Ips))
	}
	return out
}

func connectionBucketsFrom1h(rows []sqlc.ConnectionsByBuckets1hRow) []ConnectionBucketPoint {
	out := make([]ConnectionBucketPoint, 0, len(rows))
	for _, row := range rows {
		out = append(out, connectionBucketPoint(row.BucketStart, row.Ips))
	}
	return out
}

func connectionBucketsFrom6h(rows []sqlc.ConnectionsByBuckets6hRow) []ConnectionBucketPoint {
	out := make([]ConnectionBucketPoint, 0, len(rows))
	for _, row := range rows {
		out = append(out, connectionBucketPoint(row.BucketStart, row.Ips))
	}
	return out
}

func connectionBucketsFrom1d(rows []sqlc.ConnectionsByBuckets1dRow) []ConnectionBucketPoint {
	out := make([]ConnectionBucketPoint, 0, len(rows))
	for _, row := range rows {
		out = append(out, connectionBucketPoint(row.BucketStart, row.Ips))
	}
	return out
}

func bucketExpr(bucket string) (string, error) {
	switch bucket {
	case "5m", "1h", "6h", "1d":
		return bucket, nil
	default:
		return "", fmt.Errorf("unsupported bucket: %s", bucket)
	}
}
