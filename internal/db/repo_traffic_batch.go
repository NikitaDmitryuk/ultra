package db

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db/sqlc"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// RecordBatch acknowledges only a transaction that contains both deduplication and
// every aggregate. An ambiguous commit is safe to retry with the same identity.
func (r *TrafficRepo) RecordBatch(ctx context.Context, b runtimestate.TrafficBatch) error {
	if b.Version != 1 || b.CollectedAt.IsZero() {
		return errors.New("unsupported traffic batch")
	}
	// The collector's background replay and explicit recovery share this gate.
	if err := NewQuotaRepo(r.db).PreflightBatches(ctx, []runtimestate.TrafficBatch{b}); err != nil {
		return err
	}
	raw, e := json.Marshal(b)
	if e != nil {
		return e
	}
	hash := sha256.Sum256(raw)
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// Share the rotation lock so UUID changes cannot race lookup and legacy aggregates.
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365007)`); e != nil {
		return e
	}
	tag, e := tx.Exec(ctx, `INSERT INTO traffic_batches(node_id,batch_id,digest) VALUES($1,$2,$3) ON CONFLICT DO NOTHING`, b.NodeID, b.BatchID, hash[:])
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		var existing []byte
		if e = tx.QueryRow(ctx, `SELECT digest FROM traffic_batches WHERE node_id=$1 AND batch_id=$2`, b.NodeID, b.BatchID).Scan(&existing); e != nil {
			return e
		}
		if !bytes.Equal(existing, hash[:]) {
			return errors.New("traffic batch identity conflict")
		}
		return tx.Commit(ctx)
	}
	q := r.db.Queries.WithTx(tx)
	for _, s := range b.Samples {
		if strings.HasPrefix(s.ExitID, "@pool:") || s.AccountID == "" || s.UplinkBytes < 0 || s.DownlinkBytes < 0 || s.ChargeTotalBytes < 0 {
			return errors.New("invalid traffic sample")
		}
		period := s.Period
		if period == "" {
			period = b.CollectedAt.UTC().Format("2006-01")
		}
		if _, e := time.Parse("2006-01", period); e != nil {
			return e
		}
		// A restored PostgreSQL backup may predate this owner. Preserve the tombstone
		// and exit cost without recreating a VPN credential.
		if _, e = tx.Exec(ctx, `INSERT INTO traffic_accounts(account_id) VALUES($1) ON CONFLICT DO NOTHING`, s.AccountID); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO account_exit_usage(account_id,exit_id,period,uplink_bytes,downlink_bytes,charged_bytes) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(account_id,exit_id,period) DO UPDATE SET uplink_bytes=account_exit_usage.uplink_bytes+EXCLUDED.uplink_bytes,downlink_bytes=account_exit_usage.downlink_bytes+EXCLUDED.downlink_bytes,charged_bytes=GREATEST(account_exit_usage.charged_bytes,EXCLUDED.charged_bytes)`, s.AccountID, s.ExitID, period, s.UplinkBytes, s.DownlinkBytes, s.ChargeTotalBytes); e != nil {
			return e
		}
		if s.UplinkBytes == 0 && s.DownlinkBytes == 0 {
			continue
		}
		var id string
		e = tx.QueryRow(ctx, `SELECT uuid::text FROM users WHERE account_id=$1`, s.AccountID).Scan(&id)
		if errors.Is(e, pgx.ErrNoRows) {
			continue
		}
		if e != nil {
			return e
		}
		userUUID, e := toPGUUID(id)
		if e != nil {
			return e
		}
		at := b.CollectedAt.UTC()
		if e = q.InsertTrafficSample(ctx, sqlc.InsertTrafficSampleParams{UserUuid: userUUID, ExitTag: s.ExitTag, CollectedAt: toPGTime(at), UplinkBytes: s.UplinkBytes, DownlinkBytes: s.DownlinkBytes}); e != nil {
			return e
		}
		if s.ExitTag != "" {
			day := time.Date(at.Year(), at.Month(), at.Day(), 0, 0, 0, 0, time.UTC)
			if e = q.UpsertDailyRouteTraffic(ctx, sqlc.UpsertDailyRouteTrafficParams{UserUuid: userUUID, Day: pgtype.Date{Time: day, Valid: true}, ExitTag: s.ExitTag, UplinkBytes: s.UplinkBytes, DownlinkBytes: s.DownlinkBytes}); e != nil {
				return e
			}
		}
		if e = q.UpsertMonthlyTraffic(ctx, sqlc.UpsertMonthlyTrafficParams{UserUuid: userUUID, Year: int32(at.Year()), Month: int32(at.Month()), UplinkBytes: s.UplinkBytes, DownlinkBytes: s.DownlinkBytes}); e != nil {
			return e
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return fmt.Errorf("commit traffic batch: %w", e)
	}
	return nil
}
