package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

var ErrRTCCapacity = errors.New("capacity")
var ErrRTCRate = errors.New("rate_limited")

type RTCAccess struct {
	Owner      string     `json:"-"`
	Generation string     `json:"-"`
	RoomHash   []byte     `json:"-"`
	Cipher     []byte     `json:"-"`
	KeyVersion string     `json:"-"`
	Enabled    bool       `json:"enabled"`
	State      string     `json:"state"`
	ErrorCode  string     `json:"error_code"`
	Checked    *time.Time `json:"last_checked_at"`
	Updated    time.Time  `json:"updated_at"`
}
type RTCRepo struct{ db *DB }

func NewRTCRepo(d *DB) *RTCRepo { return &RTCRepo{d} }

const rtcColumns = `user_uuid::text,generation::text,room_hash,encrypted_config,key_version,enabled,state,error_code,last_checked_at,updated_at`

func scanRTC(row pgx.Row) (a RTCAccess, e error) {
	e = row.Scan(&a.Owner, &a.Generation, &a.RoomHash, &a.Cipher, &a.KeyVersion, &a.Enabled, &a.State, &a.ErrorCode, &a.Checked, &a.Updated)
	return
}
func (r *RTCRepo) Get(ctx context.Context, owner string) (RTCAccess, error) {
	return scanRTC(r.db.Pool.QueryRow(ctx, `SELECT `+rtcColumns+` FROM rtc_access WHERE user_uuid=$1`, owner))
}
func (r *RTCRepo) List(ctx context.Context) ([]RTCAccess, error) {
	rows, e := r.db.Pool.Query(ctx, `SELECT `+rtcColumns+` FROM rtc_access ORDER BY user_uuid`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []RTCAccess
	for rows.Next() {
		a, e := scanRTC(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Put serializes capacity reservations and checks eligibility in the same transaction.
func (r *RTCRepo) Put(ctx context.Context, a RTCAccess, limit int, importing bool) (RTCAccess, error) {
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return a, e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365022)`); e != nil {
		return a, e
	}
	var allowed bool
	e = tx.QueryRow(ctx, `SELECT is_active AND NOT member_pending FROM users WHERE uuid=$1 FOR UPDATE`, a.Owner).Scan(&allowed)
	if e != nil {
		return a, e
	}
	if !allowed {
		return a, ErrEnrollmentDenied
	}
	old, e := scanRTC(tx.QueryRow(ctx, `SELECT `+rtcColumns+` FROM rtc_access WHERE user_uuid=$1`, a.Owner))
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return a, e
	}
	if e == nil && !importing && time.Since(old.Updated) < time.Minute {
		return a, ErrRTCRate
	}
	var count int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM rtc_access WHERE enabled AND user_uuid<>$1`, a.Owner).Scan(&count); e != nil {
		return a, e
	}
	if count >= limit {
		return a, ErrRTCCapacity
	}
	if importing && old.Owner != "" {
		return old, nil
	}
	_, e = tx.Exec(ctx, `INSERT INTO rtc_access(user_uuid,generation,room_hash,encrypted_config,key_version) VALUES($1,$2,$3,$4,$5) ON CONFLICT(user_uuid) DO UPDATE SET generation=EXCLUDED.generation,room_hash=EXCLUDED.room_hash,encrypted_config=EXCLUDED.encrypted_config,key_version=EXCLUDED.key_version,enabled=true,state='preparing',error_code='',last_checked_at=NULL,updated_at=now()`, a.Owner, a.Generation, a.RoomHash, a.Cipher, a.KeyVersion)
	if e != nil {
		return a, e
	}
	if e = tx.Commit(ctx); e != nil {
		return a, e
	}
	return r.Get(ctx, a.Owner)
}
func (r *RTCRepo) Disable(ctx context.Context, owner string) error {
	_, e := r.db.Pool.Exec(ctx, `UPDATE rtc_access SET enabled=false,room_hash=NULL,state='disabled',error_code='',updated_at=now() WHERE user_uuid=$1`, owner)
	return e
}
func (r *RTCRepo) Observed(ctx context.Context, owner, generation, state, code string, checked *time.Time) error {
	_, e := r.db.Pool.Exec(ctx, `UPDATE rtc_access SET state=$3,error_code=$4,last_checked_at=COALESCE($5,last_checked_at) WHERE user_uuid=$1 AND generation=$2 AND enabled`, owner, generation, state, code, checked)
	return e
}
func (r *RTCRepo) Eligible(ctx context.Context, owner string) bool {
	var ok bool
	e := r.db.Pool.QueryRow(ctx, `SELECT is_active AND NOT member_pending FROM users WHERE uuid=$1`, owner).Scan(&ok)
	return e == nil && ok
}

type RTCUsage struct {
	Hour time.Time `json:"hour"`
	Up   int64     `json:"uplink_bytes"`
	Down int64     `json:"downlink_bytes"`
}

func (r *RTCRepo) SaveUsage(ctx context.Context, owner, epoch string, u RTCUsage) error {
	_, e := r.db.Pool.Exec(ctx, `INSERT INTO rtc_ingress_hourly(user_uuid,hour,epoch,uplink_bytes,downlink_bytes) SELECT uuid,$2,$3,$4,$5 FROM users WHERE uuid=$1 ON CONFLICT(user_uuid,hour,epoch) DO UPDATE SET uplink_bytes=GREATEST(rtc_ingress_hourly.uplink_bytes,EXCLUDED.uplink_bytes),downlink_bytes=GREATEST(rtc_ingress_hourly.downlink_bytes,EXCLUDED.downlink_bytes)`, owner, u.Hour, epoch, u.Up, u.Down)
	return e
}
func (r *RTCRepo) Usage(ctx context.Context, owner string) ([]RTCUsage, error) {
	rows, e := r.db.Pool.Query(ctx, `SELECT hour,sum(uplink_bytes)::bigint,sum(downlink_bytes)::bigint FROM rtc_ingress_hourly WHERE ($1='' OR user_uuid::text=$1) AND hour>=date_trunc('month',now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' GROUP BY hour ORDER BY hour`, owner)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []RTCUsage{}
	for rows.Next() {
		var u RTCUsage
		if e = rows.Scan(&u.Hour, &u.Up, &u.Down); e != nil {
			return nil, e
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

func (r *RTCRepo) IndexKey(ctx context.Context, cipher []byte, version string) ([]byte, string, error) {
	_, e := r.db.Pool.Exec(ctx, `INSERT INTO rtc_key_material(singleton,encrypted_key,key_version) VALUES(true,$1,$2) ON CONFLICT DO NOTHING`, cipher, version)
	if e != nil {
		return nil, "", e
	}
	e = r.db.Pool.QueryRow(ctx, `SELECT encrypted_key,key_version FROM rtc_key_material WHERE singleton`).Scan(&cipher, &version)
	return cipher, version, e
}

// Active distinguishes a revoked owner from a temporary pending route application.
func (r *RTCRepo) Active(ctx context.Context, owner string) (bool, error) {
	var active bool
	e := r.db.Pool.QueryRow(ctx, `SELECT is_active FROM users WHERE uuid=$1`, owner).Scan(&active)
	if errors.Is(e, pgx.ErrNoRows) {
		return false, nil
	}
	return active, e
}
