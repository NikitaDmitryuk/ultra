package db

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// queuedSQLC lets generated :exec methods append different statements to one
// pgx pipeline. It never owns a connection or transaction; the caller sends and
// checks the batch in its existing transaction before committing.
type queuedSQLC struct{ batch *pgx.Batch }

func (q *queuedSQLC) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	q.batch.Queue(query, args...)
	return pgconn.CommandTag{}, nil
}
func (*queuedSQLC) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errQueuedQuery
}
func (*queuedSQLC) QueryRow(context.Context, string, ...any) pgx.Row { return queuedErrorRow{} }

var errQueuedQuery = errors.New("SQLC pipeline supports only exec queries")

type queuedErrorRow struct{}

func (queuedErrorRow) Scan(...any) error { return errQueuedQuery }
