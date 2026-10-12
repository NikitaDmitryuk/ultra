package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
	"github.com/google/uuid"
)

// The store's exclusive file lock prevents draining a running relay. No core,
// migrations or workers start; a failed commit always leaves the batch on disk.
func drainJournal(ctx context.Context, spec *config.Spec, path string) error {
	if spec.Database == nil || spec.Database.DSN == "" {
		return errors.New("database required")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return errors.New("existing regular journal required")
	}
	state, err := runtimestate.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = state.Close() }()
	database, err := db.OpenLazy(ctx, spec.Database.DSN)
	if err != nil {
		return err
	}
	defer database.Close()
	if err := database.ValidateAccountingSchema(ctx); err != nil {
		return errors.New("compatible accounting schema required")
	}
	return drainJournalStore(ctx, state, db.NewTrafficRepo(database))
}

type journalReceiver interface {
	RecordBatch(context.Context, runtimestate.TrafficBatch) error
}

func drainJournalStore(ctx context.Context, state *runtimestate.Store, receiver journalReceiver) error {
	replay := func() error {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			batches, err := state.PendingBatches(64)
			if err != nil {
				return err
			}
			if len(batches) == 0 {
				return nil
			}
			for _, batch := range batches {
				if err := receiver.RecordBatch(ctx, batch); err != nil {
					return err
				}
				if err := state.AckBatch(batch.BatchID); err != nil {
					return err
				}
			}
		}
	}
	// Make space first, then flush reservations left by a crash or shutdown even
	// when no measured traffic batch exists. Cumulative charges are idempotent.
	if err := replay(); err != nil {
		return err
	}
	if err := state.AppendBatchFull(runtimestate.TrafficBatch{NodeID: state.NodeID(), BatchID: uuid.NewString(), CollectedAt: time.Now().UTC()}); err != nil {
		return err
	}
	return replay()
}
