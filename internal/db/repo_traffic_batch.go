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
	qtx := r.db.Queries.WithTx(tx)
	nodeID, e := toPGUUID(b.NodeID)
	if e != nil {
		return e
	}
	batchID, e := toPGUUID(b.BatchID)
	if e != nil {
		return e
	}
	// Share the rotation lock so UUID changes cannot race lookup and legacy aggregates.
	if e = qtx.LockTrafficRotation(ctx); e != nil {
		return e
	}
	inserted, e := qtx.InsertTrafficBatchIdentity(ctx, sqlc.InsertTrafficBatchIdentityParams{NodeID: nodeID, BatchID: batchID, Digest: hash[:]})
	if e != nil {
		return e
	}
	if inserted == 0 {
		existing, e := qtx.TrafficBatchDigest(ctx, sqlc.TrafficBatchDigestParams{NodeID: nodeID, BatchID: batchID})
		if e != nil {
			return e
		}
		if !bytes.Equal(existing, hash[:]) {
			return errors.New("traffic batch identity conflict")
		}
		return tx.Commit(ctx)
	}
	// Normalize a copy: the digest above remains the exact persisted batch identity.
	samples := append([]runtimestate.Sample(nil), b.Samples...)
	for i := range samples {
		s := &samples[i]
		if strings.HasPrefix(s.ExitID, "@pool:") || s.AccountID == "" || s.UplinkBytes < 0 || s.DownlinkBytes < 0 || s.ChargeTotalBytes < 0 {
			return errors.New("invalid traffic sample")
		}
		if s.Period == "" {
			s.Period = b.CollectedAt.UTC().Format("2006-01")
		}
		if _, e := time.Parse("2006-01", s.Period); e != nil {
			return e
		}
	}
	if len(samples) > 0 {
		payload, err := json.Marshal(samples)
		if err != nil {
			return err
		}
		// Separate ordered statements ensure tombstones exist before their FK users.
		// Group at each destination's key: two routes may belong to the same owner.
		// Raw rows retain the original collection time and physical route tag.
		batch := &pgx.Batch{}
		q := sqlc.New(&queuedSQLC{batch: batch})
		arg := sqlc.InsertBatchTrafficAccountsParams{Samples: payload, CollectedAt: toPGTime(b.CollectedAt.UTC())}
		if err := q.InsertBatchTrafficAccounts(ctx, arg); err != nil {
			return err
		}
		if err := q.UpsertBatchAccountUsage(ctx, sqlc.UpsertBatchAccountUsageParams(arg)); err != nil {
			return err
		}
		if err := q.InsertBatchRawTraffic(ctx, sqlc.InsertBatchRawTrafficParams(arg)); err != nil {
			return err
		}
		if err := q.UpsertBatchDailyTraffic(ctx, sqlc.UpsertBatchDailyTrafficParams(arg)); err != nil {
			return err
		}
		if err := q.UpsertBatchMonthlyTraffic(ctx, sqlc.UpsertBatchMonthlyTrafficParams(arg)); err != nil {
			return err
		}
		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return err
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return fmt.Errorf("commit traffic batch: %w", e)
	}
	return nil
}
