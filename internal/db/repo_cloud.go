package db

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
)

type CloudRepo struct{ db *DB }

func NewCloudRepo(d *DB) *CloudRepo { return &CloudRepo{db: d} }
func (r *CloudRepo) SaveOffer(ctx context.Context, o cloud.Offer) error {
	body, e := json.Marshal(o)
	if e != nil {
		return e
	}
	_, e = r.db.Pool.Exec(ctx, `INSERT INTO cloud_offers(id,actor,expires_at,body) VALUES($1,$2,$3,$4)`, o.ID, o.Actor, o.ExpiresAt, body)
	return e
}
func (r *CloudRepo) Offer(ctx context.Context, id string) (cloud.Offer, error) {
	var o cloud.Offer
	var body []byte
	e := r.db.Pool.QueryRow(ctx, `SELECT body FROM cloud_offers WHERE id=$1`, id).Scan(&body)
	if e != nil {
		return o, e
	}
	e = json.Unmarshal(body, &o)
	return o, e
}
func (r *CloudRepo) Get(ctx context.Context, id string) (cloud.Operation, error) {
	var o cloud.Operation
	var body []byte
	e := r.db.Pool.QueryRow(ctx, `SELECT body FROM cloud_operations WHERE id=$1`, id).Scan(&body)
	if e != nil {
		return o, e
	}
	e = json.Unmarshal(body, &o)
	return o, e
}
func (r *CloudRepo) List(ctx context.Context) ([]cloud.Operation, error) {
	rows, e := r.db.Pool.Query(ctx, `SELECT body FROM cloud_operations ORDER BY created_at`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []cloud.Operation{}
	for rows.Next() {
		var body []byte
		var o cloud.Operation
		if e = rows.Scan(&body); e != nil {
			return nil, e
		}
		if e = json.Unmarshal(body, &o); e != nil {
			return nil, e
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
func (r *CloudRepo) Reserve(ctx context.Context, offer cloud.Offer) (cloud.Operation, error) {
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return cloud.Operation{}, e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365005)`); e != nil {
		return cloud.Operation{}, e
	}
	var existing []byte
	e = tx.QueryRow(ctx, `SELECT body FROM cloud_operations WHERE id=$1`, offer.ID).Scan(&existing)
	if e == nil {
		var op cloud.Operation
		e = json.Unmarshal(existing, &op)
		return op, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return cloud.Operation{}, e
	}
	if offer.ReplaceID != "" {
		var replaceable bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cloud_operations WHERE id=$1 AND state='ready') AND NOT EXISTS(SELECT 1 FROM cloud_operations WHERE occupies_slot AND body->'offer'->>'replace_id'=$1)`, offer.ReplaceID).Scan(&replaceable); e != nil {
			return cloud.Operation{}, e
		}
		if !replaceable {
			return cloud.Operation{}, cloud.ErrConflict
		}
	}
	var count int
	if e = tx.QueryRow(ctx, `SELECT COUNT(*) FROM cloud_operations WHERE occupies_slot`).Scan(&count); e != nil {
		return cloud.Operation{}, e
	}
	if count >= 2 {
		return cloud.Operation{}, cloud.ErrLimit
	}
	var valid bool
	if e = tx.QueryRow(ctx, `SELECT expires_at>NOW() AND actor=$2 FROM cloud_offers WHERE id=$1`, offer.ID, offer.Actor).Scan(&valid); e != nil {
		return cloud.Operation{}, e
	}
	if !valid {
		return cloud.Operation{}, cloud.ErrPriceChanged
	}
	op := cloud.Operation{ID: offer.ID, Offer: offer, State: "pending", Phase: "prepare", CreatedAt: time.Now().UTC()}
	body, e := json.Marshal(op)
	if e != nil {
		return op, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO cloud_operations(id,state,body) VALUES($1,$2,$3)`, op.ID, op.State, body)
	if e != nil {
		return op, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO cloud_audit(actor,operation_id,action) VALUES($1,$2,'confirmed')`, offer.Actor, op.ID); e != nil {
		return op, e
	}
	return op, tx.Commit(ctx)
}
func (r *CloudRepo) Save(ctx context.Context, op cloud.Operation) error {
	body, e := json.Marshal(op)
	if e != nil {
		return e
	}
	_, e = r.db.Pool.Exec(ctx, `UPDATE cloud_operations SET state=$2,body=$3,occupies_slot=$4 WHERE id=$1`, op.ID, op.State, body, op.State != "cancelled" && op.State != "deleted")
	return e
}
func (r *CloudRepo) Lock(ctx context.Context) (func(), error) {
	conn, e := r.db.Pool.Acquire(ctx)
	if e != nil {
		return nil, e
	}
	if _, e = conn.Exec(ctx, `SELECT pg_advisory_lock(817365006)`); e != nil {
		conn.Release()
		return nil, e
	}
	return func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(c, `SELECT pg_advisory_unlock(817365006)`); err != nil {
			_ = conn.Conn().Close(c)
		}
		conn.Release()
	}, nil
}

func (r *CloudRepo) Audit(ctx context.Context, actor int64, id, action string) error {
	_, e := r.db.Pool.Exec(ctx, `INSERT INTO cloud_audit(actor,operation_id,action) VALUES($1,$2,$3)`, actor, id, action)
	return e
}

func (r *CloudRepo) RecordEvent(ctx context.Context, e cloud.Event) error {
	_, err := r.db.Pool.Exec(ctx, `INSERT INTO cloud_operation_events(operation_id,phase,outcome,code,http_status,duration_ms,created_at) VALUES($1,$2,$3,$4,$5,$6,$7)`, e.OperationID, e.Phase, e.Outcome, e.Code, e.HTTPStatus, e.DurationMS, e.At)
	return err
}
func (r *CloudRepo) Events(ctx context.Context, id string) ([]cloud.Event, error) {
	rows, e := r.db.Pool.Query(ctx, `SELECT operation_id::text,phase,outcome,code,http_status,duration_ms,created_at FROM cloud_operation_events WHERE operation_id=$1 ORDER BY id DESC LIMIT 100`, id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []cloud.Event{}
	for rows.Next() {
		var v cloud.Event
		if e = rows.Scan(&v.OperationID, &v.Phase, &v.Outcome, &v.Code, &v.HTTPStatus, &v.DurationMS, &v.At); e != nil {
			return nil, e
		}
		if v.Code != "" {
			v.Message = cloud.ErrorMessage(v.Code)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
