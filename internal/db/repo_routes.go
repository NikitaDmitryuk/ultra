package db

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type RouteRepo struct{ db *DB }

func NewRouteRepo(d *DB) *RouteRepo { return &RouteRepo{db: d} }
func (r *RouteRepo) Attach(ctx context.Context, users []auth.User) ([]auth.User, error) {
	var rows []struct {
		UserUUID   string `gorm:"column:user_uuid"`
		UUID       string
		LocationID string
		Name       string
		ExitID     *string
		Published  bool
	}
	e := r.db.orm.WithContext(ctx).Table("vpn_route_credentials AS c").Select("c.user_uuid, c.uuid, l.id AS location_id, l.name, l.exit_id, (l.published AND l.applied) AS published").Joins("JOIN vpn_locations l ON l.id = c.location_id").Order("l.name, c.uuid").Find(&rows).Error
	if e != nil {
		return nil, e
	}
	byOwner := map[string][]auth.RouteCredential{}
	for _, row := range rows {
		byOwner[row.UserUUID] = append(byOwner[row.UserUUID], auth.RouteCredential{UUID: row.UUID, LocationID: row.LocationID, Name: row.Name, ExitID: row.ExitID, Published: row.Published})
	}

	for i := range users {
		users[i].Routes = byOwner[users[i].UUID]
	}
	var quotaRows []struct {
		UUID   string
		ExitID string
		Reason string
	}
	e = r.db.orm.WithContext(ctx).Table("users AS u").Select("u.uuid, b.exit_id, COALESCE(NULLIF(q.reason, ''), 'quota_pending') AS reason").Joins("CROSS JOIN exit_traffic_budgets b").Joins("LEFT JOIN user_exit_quotas q ON q.user_uuid = u.uuid AND q.exit_id = b.exit_id").Where("COALESCE(q.blocked, true)").Find(&quotaRows).Error
	if e != nil {
		return nil, e
	}
	blocked := map[string][]string{}
	reasons := map[string]map[string]string{}
	for _, row := range quotaRows {
		blocked[row.UUID] = append(blocked[row.UUID], row.ExitID)
		if reasons[row.UUID] == nil {
			reasons[row.UUID] = map[string]string{}
		}
		reasons[row.UUID][row.ExitID] = row.Reason
	}
	var fallbackRows []struct{ ExitID string }
	if e = r.db.orm.WithContext(ctx).Table("exit_traffic_budgets").Select("exit_id").Where("is_fallback").Find(&fallbackRows).Error; e != nil {
		return nil, e
	}
	fallback := ""
	if len(fallbackRows) > 0 {
		fallback = fallbackRows[0].ExitID
	}

	for i := range users {
		users[i].FallbackExitID = fallback
		users[i].ExcludedExitIDs = blocked[users[i].UUID]
		users[i].ExitExclusionReasons = reasons[users[i].UUID]
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
	_, e = tx.Exec(ctx, `INSERT INTO vpn_route_credentials(uuid,user_uuid,location_id) SELECT gen_random_uuid(),uuid,$1 FROM users WHERE kind='vless' AND NOT EXISTS(SELECT 1 FROM service_access s WHERE s.account_id=users.account_id) ON CONFLICT DO NOTHING`, id)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (r *RouteRepo) Unpublish(ctx context.Context, exitID string) error {
	return r.db.orm.WithContext(ctx).Table("vpn_locations").Where("exit_id = ?", exitID).Updates(map[string]any{"published": false, "exit_id": nil}).Error
}
func (r *RouteRepo) SetPin(ctx context.Context, exitID, pin string) error {
	return r.db.orm.WithContext(ctx).Table("exit_nodes").Where("id = ?", exitID).Update("pinned_peer_cert_sha256", pin).Error
}

func (r *RouteRepo) Applied(ctx context.Context, exitID string) error {
	return r.db.orm.WithContext(ctx).Table("vpn_locations").Where("exit_id = ?", exitID).Update("applied", true).Error
}

func (r *RouteRepo) ReplicationState(ctx context.Context, id, state string, free, required int64, detail string) error {
	row := map[string]any{"node_id": id, "state": state, "free_bytes": free, "required_bytes": required, "detail": detail}
	updates := map[string]any{"state": state, "detail": detail, "checked_at": gorm.Expr("NOW()")}
	if free > 0 {
		updates["free_bytes"] = free
	}
	if required > 0 {
		updates["required_bytes"] = required
	}
	return r.db.orm.WithContext(ctx).Table("node_replication").Clauses(clause.OnConflict{Columns: []clause.Column{{Name: "node_id"}}, DoUpdates: clause.Assignments(updates)}).Create(row).Error
}

func (r *RouteRepo) ReplicationStatuses(ctx context.Context) (any, error) {

	type item struct {
		ID        string     `json:"id"`
		Name      string     `json:"name"`
		State     string     `json:"state"`
		Free      int64      `json:"free_bytes"`
		Required  int64      `json:"required_bytes"`
		CheckedAt *time.Time `json:"checked_at"`
	}
	out := []item{}
	e := r.db.orm.WithContext(ctx).Table("exit_nodes AS e").Select("e.id, COALESCE(NULLIF(e.display_name, ''), NULLIF(e.city, ''), e.name) AS name, CASE WHEN n.checked_at < NOW() - INTERVAL '90 seconds' THEN 'stale' ELSE COALESCE(n.state, 'not_configured') END AS state, COALESCE(n.free_bytes, 0) AS free, COALESCE(n.required_bytes, 0) AS required, n.checked_at").Joins("LEFT JOIN node_replication n ON n.node_id = e.id").Order("e.name").Find(&out).Error
	return out, e
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
	_, e = tx.Exec(ctx, `INSERT INTO vpn_route_credentials(uuid,user_uuid,location_id) SELECT gen_random_uuid(),u.uuid,l.id FROM users u CROSS JOIN vpn_locations l WHERE u.kind='vless' AND l.provider_region IS NULL AND l.published AND NOT EXISTS(SELECT 1 FROM service_access s WHERE s.account_id=u.account_id) ON CONFLICT DO NOTHING`)
	if e != nil {
		return e
	}
	return tx.Commit(ctx)
}
func (r *RouteRepo) AppliedManual(ctx context.Context) error {
	return r.db.orm.WithContext(ctx).Table("vpn_locations").Where("provider_region IS NULL AND published AND NOT applied").Update("applied", true).Error
}
