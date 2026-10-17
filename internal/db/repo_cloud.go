package db

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/db/sqlc"
	"github.com/jackc/pgx/v5"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type CloudRepo struct{ db *DB }

func NewCloudRepo(d *DB) *CloudRepo { return &CloudRepo{db: d} }
func (r *CloudRepo) SaveOffer(ctx context.Context, o cloud.Offer) error {
	var err error
	o, err = canonicalCloudOffer(o)
	if err != nil {
		return err
	}
	body, e := json.Marshal(o)
	if e != nil {
		return e
	}
	return r.db.orm.WithContext(ctx).Create(&cloudOfferRow{ID: o.ID, Actor: o.Actor, ExpiresAt: o.ExpiresAt, Body: body}).Error
}

// PostgreSQL identifiers are UUID values. Persist the same canonical identity in
// JSON so spelling differences cannot create separate replacement reservations.
func canonicalCloudOffer(o cloud.Offer) (cloud.Offer, error) {
	if o.ReplaceID != "" {
		id, err := toPGUUID(o.ReplaceID)
		if err != nil {
			return o, err
		}
		o.ReplaceID = fromPGUUID(id)
	}
	return o, nil
}

func cloudID(id string) clause.Eq {
	return clause.Eq{Column: clause.Column{Name: "id"}, Value: id}
}
func cloudLookupError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return pgx.ErrNoRows
	}
	return err
}
func (r *CloudRepo) Offer(ctx context.Context, id string) (cloud.Offer, error) {
	var o cloud.Offer
	var row cloudOfferRow
	if e := r.db.orm.WithContext(ctx).Select("body").Where(cloudID(id)).Take(&row).Error; e != nil {
		return o, cloudLookupError(e)
	}
	err := json.Unmarshal(row.Body, &o)
	return o, err
}
func (r *CloudRepo) Get(ctx context.Context, id string) (cloud.Operation, error) {
	var o cloud.Operation
	var row cloudOperationRow
	if e := r.db.orm.WithContext(ctx).Select("body").Where(cloudID(id)).Take(&row).Error; e != nil {
		return o, cloudLookupError(e)
	}
	err := json.Unmarshal(row.Body, &o)
	return o, err
}
func (r *CloudRepo) List(ctx context.Context) ([]cloud.Operation, error) {
	rows := []cloudOperationRow{}
	if e := r.db.orm.WithContext(ctx).Select("body").Order(clause.OrderByColumn{Column: clause.Column{Name: "created_at"}}).Find(&rows).Error; e != nil {
		return nil, e
	}
	out := make([]cloud.Operation, 0, len(rows))
	for _, row := range rows {
		var o cloud.Operation
		if e := json.Unmarshal(row.Body, &o); e != nil {
			return nil, e
		}
		out = append(out, o)
	}
	return out, nil
}

func (r *CloudRepo) Reserve(ctx context.Context, offer cloud.Offer) (cloud.Operation, error) {
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return cloud.Operation{}, e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	qtx := r.db.Queries.WithTx(tx)
	offerID, e := toPGUUID(offer.ID)
	if e != nil {
		return cloud.Operation{}, e
	}
	if e = qtx.LockCloudReservation(ctx); e != nil {
		return cloud.Operation{}, e
	}
	existing, e := qtx.CloudOperationBody(ctx, offerID)
	if e == nil {
		var op cloud.Operation
		e = json.Unmarshal(existing, &op)
		return op, e
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return cloud.Operation{}, e
	}
	if offer.ReplaceID != "" {
		replaceID, e := toPGUUID(offer.ReplaceID)
		if e != nil {
			return cloud.Operation{}, e
		}
		replaceable, e := qtx.CloudReplacementEligible(ctx, replaceID)
		if e != nil {
			return cloud.Operation{}, e
		}
		if !replaceable.Bool {
			return cloud.Operation{}, cloud.ErrConflict
		}
		offer.ReplaceID = fromPGUUID(replaceID)
	}
	count, e := qtx.CloudOccupiedSlots(ctx)
	if e != nil {
		return cloud.Operation{}, e
	}
	if count >= int64(cloud.MaxServers) {
		return cloud.Operation{}, cloud.ErrLimit
	}
	valid, e := qtx.CloudOfferValid(ctx, sqlc.CloudOfferValidParams{ID: offerID, Actor: offer.Actor})
	if e != nil {
		return cloud.Operation{}, e
	}
	if !valid.Bool {
		return cloud.Operation{}, cloud.ErrPriceChanged
	}
	op := cloud.Operation{ID: offer.ID, Offer: offer, State: "pending", Phase: "prepare", CreatedAt: time.Now().UTC()}
	body, e := json.Marshal(op)
	if e != nil {
		return op, e
	}
	e = qtx.InsertReservedCloudOperation(ctx, sqlc.InsertReservedCloudOperationParams{ID: offerID, State: op.State, Body: body})
	if e != nil {
		return op, e
	}
	if e = qtx.InsertCloudConfirmation(ctx, sqlc.InsertCloudConfirmationParams{Actor: offer.Actor, OperationID: offerID}); e != nil {
		return op, e
	}
	return op, tx.Commit(ctx)
}
func (r *CloudRepo) Save(ctx context.Context, op cloud.Operation) error {
	var err error
	op.Offer, err = canonicalCloudOffer(op.Offer)
	if err != nil {
		return err
	}
	body, e := json.Marshal(op)
	if e != nil {
		return e
	}
	row := cloudOperationRow{State: op.State, Body: body, OccupiesSlot: op.State != "cancelled" && op.State != "deleted"}
	result := r.db.orm.WithContext(ctx).Where(cloudID(op.ID)).
		Where("COALESCE(body->>'reinstall_job_id','') = ? AND COALESCE(body->>'reinstall_target','') = ?", op.ReinstallJobID, op.ReinstallTarget).
		Select("state", "body", "occupies_slot").Updates(&row)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected != 1 {
		return cloud.ErrConflict
	}
	return nil
}

func (r *CloudRepo) Lock(ctx context.Context) (func(), error) {
	conn, e := r.db.Pool.Acquire(ctx)
	if e != nil {
		return nil, e
	}
	q := sqlc.New(conn)
	if e = q.LockCloudWorker(ctx); e != nil {
		conn.Release()
		return nil, e
	}
	return func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := q.UnlockCloudWorker(c); err != nil {
			_ = conn.Conn().Close(c)
		}
		conn.Release()
	}, nil
}

func (r *CloudRepo) Audit(ctx context.Context, actor int64, id, action string) error {
	return r.db.orm.WithContext(ctx).Create(&cloudAuditRow{Actor: actor, OperationID: id, Action: action}).Error
}

func (r *CloudRepo) RecordEvent(ctx context.Context, e cloud.Event) error {
	return r.db.orm.WithContext(ctx).
		Create(&cloudEventRow{OperationID: e.OperationID, Phase: e.Phase, Outcome: e.Outcome, Code: e.Code, HTTPStatus: e.HTTPStatus, DurationMS: e.DurationMS, CreatedAt: e.At}).
		Error
}
func (r *CloudRepo) Events(ctx context.Context, id string) ([]cloud.Event, error) {
	rows := []cloudEventRow{}
	if e := r.db.orm.WithContext(ctx).Where(clause.Eq{Column: clause.Column{Name: "operation_id"}, Value: id}).Order(clause.OrderByColumn{Column: clause.Column{Name: "id"}, Desc: true}).Limit(100).Find(&rows).Error; e != nil {
		return nil, e
	}
	out := make([]cloud.Event, 0, len(rows))
	for _, row := range rows {
		v := cloud.Event{
			OperationID: row.OperationID,
			Phase:       row.Phase,
			Outcome:     row.Outcome,
			Code:        row.Code,
			HTTPStatus:  row.HTTPStatus,
			DurationMS:  row.DurationMS,
			At:          row.CreatedAt,
		}
		if v.Code != "" {
			v.Message = cloud.ErrorMessage(v.Code)
		}
		out = append(out, v)
	}
	return out, nil
}
