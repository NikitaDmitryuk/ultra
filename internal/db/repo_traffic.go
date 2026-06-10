package db

import (
	"context"
	"fmt"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// TrafficSample is a single per-user traffic delta collected from Xray.
type TrafficSample struct {
	UserUUID      string
	CollectedAt   time.Time
	UplinkBytes   int64
	DownlinkBytes int64
}

// MonthlyTotal holds aggregated traffic for a user in one calendar month.
type MonthlyTotal struct {
	UserUUID      string
	Year          int
	Month         int
	UplinkBytes   int64
	DownlinkBytes int64
	TotalBytes    int64
}

// MonthlyHistoryPoint holds total traffic across all users for one calendar month.
type MonthlyHistoryPoint struct {
	Year          int
	Month         int
	UplinkBytes   int64
	DownlinkBytes int64
	TotalBytes    int64
}

// TrafficTimelinePoint holds per-user traffic aggregated into a time bucket.
type TrafficTimelinePoint struct {
	BucketStart   time.Time `json:"bucket_start"`
	UplinkBytes   int64     `json:"uplink_bytes"`
	DownlinkBytes int64     `json:"downlink_bytes"`
	TotalBytes    int64     `json:"total_bytes"`
}

// UserLastSeen holds the most recent activity timestamp for a user.
type UserLastSeen struct {
	UserUUID string
	LastSeen time.Time
}

// TrafficRepo handles traffic stats storage.
type TrafficRepo struct {
	db *DB
}

// NewTrafficRepo creates a TrafficRepo backed by db.
func NewTrafficRepo(db *DB) *TrafficRepo { return &TrafficRepo{db: db} }

// TrafficTimelineByBuckets exposes the Mini App traffic timeline through the
// TelegramRepo, which already owns the bot-side database connection.
func (r *TelegramRepo) TrafficTimelineByBuckets(
	ctx context.Context,
	userUUID string,
	window time.Duration,
	bucket string,
) ([]TrafficTimelinePoint, error) {
	return trafficTimelineByBuckets(ctx, r.db.Queries, userUUID, window, bucket)
}

func trafficBucketExpr(bucket string) (string, error) {
	switch bucket {
	case "5m", "1h", "6h", "1d":
		return bucket, nil
	default:
		return "", fmt.Errorf("unsupported bucket: %s", bucket)
	}
}

// RecordSamples inserts raw traffic deltas and atomically updates monthly aggregates.
// Samples with both counters at zero are skipped.
func (r *TrafficRepo) RecordSamples(ctx context.Context, samples []TrafficSample) error {
	for _, s := range samples {
		if s.UplinkBytes == 0 && s.DownlinkBytes == 0 {
			continue
		}
		userUUID, err := toPGUUID(s.UserUUID)
		if err != nil {
			return err
		}
		if err := r.db.Queries.InsertTrafficSample(ctx, sqlc.InsertTrafficSampleParams{
			UserUuid:      userUUID,
			CollectedAt:   toPGTime(s.CollectedAt),
			UplinkBytes:   s.UplinkBytes,
			DownlinkBytes: s.DownlinkBytes,
		}); err != nil {
			return err
		}
		year, month, _ := s.CollectedAt.Date()
		if err := r.db.Queries.UpsertMonthlyTraffic(ctx, sqlc.UpsertMonthlyTrafficParams{
			UserUuid:      userUUID,
			Year:          int32(year),
			Month:         int32(month),
			UplinkBytes:   s.UplinkBytes,
			DownlinkBytes: s.DownlinkBytes,
		}); err != nil {
			return err
		}
	}
	return nil
}

// GetMonthlyAll returns monthly totals for every user in the given year/month.
func (r *TrafficRepo) GetMonthlyAll(ctx context.Context, year, month int) ([]MonthlyTotal, error) {
	rows, err := r.db.Queries.GetMonthlyAll(ctx, sqlc.GetMonthlyAllParams{Year: int32(year), Month: int32(month)})
	if err != nil {
		return nil, err
	}
	out := make([]MonthlyTotal, 0, len(rows))
	for _, row := range rows {
		t := MonthlyTotal{
			UserUUID:      fromPGUUID(row.UserUuid),
			Year:          int(row.Year),
			Month:         int(row.Month),
			UplinkBytes:   row.UplinkBytes,
			DownlinkBytes: row.DownlinkBytes,
		}
		t.TotalBytes = t.UplinkBytes + t.DownlinkBytes
		out = append(out, t)
	}
	return out, nil
}

// GetMonthlyUser returns the monthly total for a single user.
// Returns zero MonthlyTotal (not an error) when no data exists yet.
func (r *TrafficRepo) GetMonthlyUser(ctx context.Context, userUUID string, year, month int) (MonthlyTotal, error) {
	pgUUID, err := toPGUUID(userUUID)
	if err != nil {
		return MonthlyTotal{UserUUID: userUUID, Year: year, Month: month}, err
	}
	row, err := r.db.Queries.GetMonthlyUser(ctx, sqlc.GetMonthlyUserParams{UserUuid: pgUUID, Year: int32(year), Month: int32(month)})
	if err != nil {
		// No row yet → return zero value
		if err == pgx.ErrNoRows {
			return MonthlyTotal{UserUUID: userUUID, Year: year, Month: month}, nil
		}
		return MonthlyTotal{UserUUID: userUUID, Year: year, Month: month}, nil
	}
	t := MonthlyTotal{
		UserUUID:      fromPGUUID(row.UserUuid),
		Year:          int(row.Year),
		Month:         int(row.Month),
		UplinkBytes:   row.UplinkBytes,
		DownlinkBytes: row.DownlinkBytes,
	}
	t.TotalBytes = t.UplinkBytes + t.DownlinkBytes
	return t, nil
}

// GetMonthlyHistory returns total traffic across all users for the last N calendar months,
// sorted from oldest to newest.
func (r *TrafficRepo) GetMonthlyHistory(ctx context.Context, months int) ([]MonthlyHistoryPoint, error) {
	rows, err := r.db.Queries.GetMonthlyHistory(ctx, int32(months))
	if err != nil {
		return nil, err
	}
	out := make([]MonthlyHistoryPoint, 0, len(rows))
	for _, row := range rows {
		p := MonthlyHistoryPoint{
			Year:          int(row.Year),
			Month:         int(row.Month),
			UplinkBytes:   row.UplinkBytes,
			DownlinkBytes: row.DownlinkBytes,
		}
		p.TotalBytes = p.UplinkBytes + p.DownlinkBytes
		out = append(out, p)
	}
	// Reverse so result is oldest→newest.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// TrafficTimelineByBuckets returns per-user raw traffic deltas aggregated into
// buckets over the requested window.
func (r *TrafficRepo) TrafficTimelineByBuckets(
	ctx context.Context,
	userUUID string,
	window time.Duration,
	bucket string,
) ([]TrafficTimelinePoint, error) {
	return trafficTimelineByBuckets(ctx, r.db.Queries, userUUID, window, bucket)
}

// PruneOldSamples deletes raw traffic samples older than the given retention period.
// Monthly aggregates in monthly_traffic are not affected — they are permanent.
// Returns the number of rows deleted.
func (r *TrafficRepo) PruneOldSamples(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention)
	return r.db.Queries.PruneOldTrafficSamples(ctx, toPGTime(cutoff))
}

// GetLastSeenAll returns the most recent activity timestamp for each user that has ever
// transferred traffic. Users with no traffic samples are omitted.
func (r *TrafficRepo) GetLastSeenAll(ctx context.Context) ([]UserLastSeen, error) {
	rows, err := r.db.Queries.GetLastSeenAll(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]UserLastSeen, 0, len(rows))
	for _, row := range rows {
		out = append(out, UserLastSeen{UserUUID: fromPGUUID(row.UserUuid), LastSeen: timeFromPG(row.LastSeen)})
	}
	return out, nil
}

func trafficTimelineByBuckets(ctx context.Context, q *sqlc.Queries, userUUID string, window time.Duration, bucket string) ([]TrafficTimelinePoint, error) {
	pgUUID, err := toPGUUID(userUUID)
	if err != nil {
		return nil, err
	}
	interval := toPGInterval(window)
	var queryErr error
	var out []TrafficTimelinePoint
	switch bucket {
	case "5m":
		var rows []sqlc.TrafficTimeline5mRow
		rows, queryErr = q.TrafficTimeline5m(ctx, sqlc.TrafficTimeline5mParams{UserUuid: pgUUID, Column2: interval})
		out = trafficTimelineFrom5m(rows)
	case "1h":
		var rows []sqlc.TrafficTimeline1hRow
		rows, queryErr = q.TrafficTimeline1h(ctx, sqlc.TrafficTimeline1hParams{UserUuid: pgUUID, Column2: interval})
		out = trafficTimelineFrom1h(rows)
	case "6h":
		var rows []sqlc.TrafficTimeline6hRow
		rows, queryErr = q.TrafficTimeline6h(ctx, sqlc.TrafficTimeline6hParams{UserUuid: pgUUID, Column2: interval})
		out = trafficTimelineFrom6h(rows)
	case "1d":
		var rows []sqlc.TrafficTimeline1dRow
		rows, queryErr = q.TrafficTimeline1d(ctx, sqlc.TrafficTimeline1dParams{UserUuid: pgUUID, Column2: interval})
		out = trafficTimelineFrom1d(rows)
	default:
		return nil, fmt.Errorf("unsupported bucket: %s", bucket)
	}
	if queryErr != nil {
		return nil, queryErr
	}
	return out, nil
}

func trafficTimelinePoint(bucketStart pgtype.Timestamptz, uplink, downlink int64) TrafficTimelinePoint {
	p := TrafficTimelinePoint{BucketStart: timeFromPG(bucketStart), UplinkBytes: uplink, DownlinkBytes: downlink}
	p.TotalBytes = p.UplinkBytes + p.DownlinkBytes
	return p
}

func trafficTimelineFrom5m(rows []sqlc.TrafficTimeline5mRow) []TrafficTimelinePoint {
	out := make([]TrafficTimelinePoint, 0, len(rows))
	for _, row := range rows {
		out = append(out, trafficTimelinePoint(row.BucketStart, row.UplinkBytes, row.DownlinkBytes))
	}
	return out
}

func trafficTimelineFrom1h(rows []sqlc.TrafficTimeline1hRow) []TrafficTimelinePoint {
	out := make([]TrafficTimelinePoint, 0, len(rows))
	for _, row := range rows {
		out = append(out, trafficTimelinePoint(row.BucketStart, row.UplinkBytes, row.DownlinkBytes))
	}
	return out
}

func trafficTimelineFrom6h(rows []sqlc.TrafficTimeline6hRow) []TrafficTimelinePoint {
	out := make([]TrafficTimelinePoint, 0, len(rows))
	for _, row := range rows {
		out = append(out, trafficTimelinePoint(row.BucketStart, row.UplinkBytes, row.DownlinkBytes))
	}
	return out
}

func trafficTimelineFrom1d(rows []sqlc.TrafficTimeline1dRow) []TrafficTimelinePoint {
	out := make([]TrafficTimelinePoint, 0, len(rows))
	for _, row := range rows {
		out = append(out, trafficTimelinePoint(row.BucketStart, row.UplinkBytes, row.DownlinkBytes))
	}
	return out
}
