package db

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/google/uuid"
)

type RouteRepo struct{ db *DB }

func NewRouteRepo(d *DB) *RouteRepo { return &RouteRepo{db: d} }
func (r *RouteRepo) Attach(ctx context.Context, users []auth.User) ([]auth.User, error) {
	rows, e := r.db.Pool.Query(ctx, `SELECT c.user_uuid::text,c.uuid::text,l.id::text,l.name,l.exit_id::text,(l.published AND l.applied) FROM vpn_route_credentials c JOIN vpn_locations l ON l.id=c.location_id ORDER BY l.name,c.uuid`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	byOwner := map[string][]auth.RouteCredential{}
	for rows.Next() {
		var owner string
		var p auth.RouteCredential
		if e = rows.Scan(&owner, &p.UUID, &p.LocationID, &p.Name, &p.ExitID, &p.Published); e != nil {
			return nil, e
		}
		byOwner[owner] = append(byOwner[owner], p)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	for i := range users {
		users[i].Routes = byOwner[users[i].UUID]
	}
	return users, nil
}
func (r *RouteRepo) Publish(ctx context.Context, region, name, exitID string) error {
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365007)`); e != nil {
		return e
	}
	var location, oldExit *string
	e = tx.QueryRow(ctx, `SELECT id::text,exit_id::text FROM vpn_locations WHERE provider_region=$1 FOR UPDATE`, region).Scan(&location, &oldExit)
	if e != nil && !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	id := uuid.NewString()
	if location != nil {
		id = *location
	}
	_, e = tx.Exec(ctx, `INSERT INTO vpn_locations(id,provider_region,name,exit_id,published) VALUES($1,$2,$3,$4,true)
 ON CONFLICT(provider_region) DO UPDATE SET name=EXCLUDED.name,exit_id=EXCLUDED.exit_id,published=true,applied=false`, id, region, name, exitID)
	if e != nil {
		return e
	}
	if oldExit != nil && *oldExit != exitID {
		if _, e = tx.Exec(ctx, `UPDATE users SET preferred_exit_id=$2 WHERE preferred_exit_id=$1`, *oldExit, exitID); e != nil {
			return e
		}
	}
	_, e = tx.Exec(ctx, `INSERT INTO vpn_route_credentials(uuid,user_uuid,location_id) SELECT gen_random_uuid(),uuid,$1 FROM users WHERE kind='vless' ON CONFLICT DO NOTHING`, id)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (r *RouteRepo) Unpublish(ctx context.Context, exitID string) error {
	_, e := r.db.Pool.Exec(ctx, `UPDATE vpn_locations SET published=false,exit_id=NULL WHERE exit_id=$1`, exitID)
	return e
}
func (r *RouteRepo) SetPin(ctx context.Context, exitID, pin string) error {
	_, e := r.db.Pool.Exec(ctx, `UPDATE exit_nodes SET pinned_peer_cert_sha256=$2 WHERE id=$1`, exitID, pin)
	return e
}

func (r *RouteRepo) Applied(ctx context.Context, exitID string) error {
	_, e := r.db.Pool.Exec(ctx, `UPDATE vpn_locations SET applied=true WHERE exit_id=$1`, exitID)
	return e
}

func (r *RouteRepo) ReplicationState(ctx context.Context, id, state string, free, required int64, detail string) error {
	_, e := r.db.Pool.Exec(ctx, `INSERT INTO node_replication(node_id,state,free_bytes,required_bytes,detail) VALUES($1,$2,$3,$4,$5)
 ON CONFLICT(node_id) DO UPDATE SET state=$2,free_bytes=CASE WHEN $3>0 THEN $3 ELSE node_replication.free_bytes END,
 required_bytes=CASE WHEN $4>0 THEN $4 ELSE node_replication.required_bytes END,detail=$5,checked_at=NOW()`, id, state, free, required, detail)
	return e
}

func (r *RouteRepo) ReplicationStatuses(ctx context.Context) (any, error) {
	rows, e := r.db.Pool.Query(ctx, `SELECT e.id::text,e.name,COALESCE(n.state,'not_configured'),COALESCE(n.free_bytes,0),COALESCE(n.required_bytes,0),n.checked_at FROM exit_nodes e LEFT JOIN node_replication n ON n.node_id=e.id ORDER BY e.name`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	type item struct {
		ID        string     `json:"id"`
		Name      string     `json:"name"`
		State     string     `json:"state"`
		Free      int64      `json:"free_bytes"`
		Required  int64      `json:"required_bytes"`
		CheckedAt *time.Time `json:"checked_at"`
	}
	out := []item{}
	for rows.Next() {
		var i item
		if e = rows.Scan(&i.ID, &i.Name, &i.State, &i.Free, &i.Required, &i.CheckedAt); e != nil {
			return nil, e
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// PrepareManual preserves the local installer path without exposing a manual cloud UI.
// Called on configuration application, never by cabinet or subscription reads.
func (r *RouteRepo) PrepareManual(ctx context.Context) error {
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365007)`); e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO vpn_locations(id,name,exit_id,published)
 SELECT e.id,COALESCE(NULLIF(e.display_name,''),NULLIF(e.city,''),e.name),e.id,true FROM exit_nodes e
 WHERE e.enabled AND NOT EXISTS(SELECT 1 FROM cloud_operations o WHERE o.id=e.id)
 ON CONFLICT(id) DO UPDATE SET name=EXCLUDED.name,exit_id=EXCLUDED.exit_id,published=true
 WHERE vpn_locations.name IS DISTINCT FROM EXCLUDED.name OR vpn_locations.exit_id IS DISTINCT FROM EXCLUDED.exit_id OR NOT vpn_locations.published`)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `UPDATE vpn_locations l SET published=false WHERE provider_region IS NULL AND published AND NOT EXISTS(SELECT 1 FROM exit_nodes e WHERE e.id=l.exit_id AND enabled)`)
	if e != nil {
		return e
	}
	_, e = tx.Exec(ctx, `INSERT INTO vpn_route_credentials(uuid,user_uuid,location_id) SELECT gen_random_uuid(),u.uuid,l.id FROM users u CROSS JOIN vpn_locations l WHERE u.kind='vless' AND l.provider_region IS NULL AND l.published ON CONFLICT DO NOTHING`)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (r *RouteRepo) AppliedManual(ctx context.Context) error {
	_, e := r.db.Pool.Exec(ctx, `UPDATE vpn_locations SET applied=true WHERE provider_region IS NULL AND published AND NOT applied`)
	return e
}
