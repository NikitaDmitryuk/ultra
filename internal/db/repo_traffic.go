package db

import (
	"context"
	"time"
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

// RecordSamples inserts raw traffic deltas and atomically updates monthly aggregates.
// Samples with both counters at zero are skipped.
func (r *TrafficRepo) RecordSamples(ctx context.Context, samples []TrafficSample) error {
	for _, s := range samples {
		if s.UplinkBytes == 0 && s.DownlinkBytes == 0 {
			continue
		}
		if _, err := r.db.Pool.Exec(ctx,
			`INSERT INTO traffic_stats(user_uuid, collected_at, uplink_bytes, downlink_bytes)
			 VALUES($1, $2, $3, $4)`,
			s.UserUUID, s.CollectedAt, s.UplinkBytes, s.DownlinkBytes,
		); err != nil {
			return err
		}
		year, month, _ := s.CollectedAt.Date()
		if _, err := r.db.Pool.Exec(ctx,
			`INSERT INTO monthly_traffic(user_uuid, year, month, uplink_bytes, downlink_bytes, updated_at)
			 VALUES($1, $2, $3, $4, $5, NOW())
			 ON CONFLICT(user_uuid, year, month) DO UPDATE SET
			   uplink_bytes   = monthly_traffic.uplink_bytes   + EXCLUDED.uplink_bytes,
			   downlink_bytes = monthly_traffic.downlink_bytes + EXCLUDED.downlink_bytes,
			   updated_at     = NOW()`,
			s.UserUUID, year, int(month), s.UplinkBytes, s.DownlinkBytes,
		); err != nil {
			return err
		}
	}
	return nil
}

// GetMonthlyAll returns monthly totals for every user in the given year/month.
func (r *TrafficRepo) GetMonthlyAll(ctx context.Context, year, month int) ([]MonthlyTotal, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT user_uuid, year, month, uplink_bytes, downlink_bytes
		 FROM monthly_traffic WHERE year=$1 AND month=$2 ORDER BY user_uuid`,
		year, month,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MonthlyTotal
	for rows.Next() {
		var t MonthlyTotal
		if err := rows.Scan(&t.UserUUID, &t.Year, &t.Month, &t.UplinkBytes, &t.DownlinkBytes); err != nil {
			return nil, err
		}
		t.TotalBytes = t.UplinkBytes + t.DownlinkBytes
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetMonthlyUser returns the monthly total for a single user.
// Returns zero MonthlyTotal (not an error) when no data exists yet.
func (r *TrafficRepo) GetMonthlyUser(ctx context.Context, userUUID string, year, month int) (MonthlyTotal, error) {
	var t MonthlyTotal
	err := r.db.Pool.QueryRow(ctx,
		`SELECT user_uuid, year, month, uplink_bytes, downlink_bytes
		 FROM monthly_traffic WHERE user_uuid=$1 AND year=$2 AND month=$3`,
		userUUID, year, month,
	).Scan(&t.UserUUID, &t.Year, &t.Month, &t.UplinkBytes, &t.DownlinkBytes)
	if err != nil {
		// No row yet → return zero value
		return MonthlyTotal{UserUUID: userUUID, Year: year, Month: month}, nil
	}
	t.TotalBytes = t.UplinkBytes + t.DownlinkBytes
	return t, nil
}

// GetMonthlyHistory returns total traffic across all users for the last N calendar months,
// sorted from oldest to newest.
func (r *TrafficRepo) GetMonthlyHistory(ctx context.Context, months int) ([]MonthlyHistoryPoint, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT year, month,
		        SUM(uplink_bytes)   AS uplink_bytes,
		        SUM(downlink_bytes) AS downlink_bytes
		 FROM monthly_traffic
		 GROUP BY year, month
		 ORDER BY year DESC, month DESC
		 LIMIT $1`,
		months,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MonthlyHistoryPoint
	for rows.Next() {
		var p MonthlyHistoryPoint
		if err := rows.Scan(&p.Year, &p.Month, &p.UplinkBytes, &p.DownlinkBytes); err != nil {
			return nil, err
		}
		p.TotalBytes = p.UplinkBytes + p.DownlinkBytes
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Reverse so result is oldest→newest.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// PruneOldSamples deletes raw traffic samples older than the given retention period.
// Monthly aggregates in monthly_traffic are not affected — they are permanent.
// Returns the number of rows deleted.
func (r *TrafficRepo) PruneOldSamples(ctx context.Context, retention time.Duration) (int64, error) {
	cutoff := time.Now().Add(-retention)
	tag, err := r.db.Pool.Exec(ctx,
		`DELETE FROM traffic_stats WHERE collected_at < $1`, cutoff,
	)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// GetLastSeenAll returns the most recent activity timestamp for each user that has ever
// transferred traffic. Users with no traffic samples are omitted.
func (r *TrafficRepo) GetLastSeenAll(ctx context.Context) ([]UserLastSeen, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT user_uuid, MAX(collected_at) AS last_seen
		 FROM traffic_stats
		 WHERE uplink_bytes + downlink_bytes > 0
		 GROUP BY user_uuid`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserLastSeen
	for rows.Next() {
		var s UserLastSeen
		if err := rows.Scan(&s.UserUUID, &s.LastSeen); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}
