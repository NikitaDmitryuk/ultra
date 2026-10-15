package db

import (
	"context"
	"errors"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/db/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/xtls/xray-core/common/uuid"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// UserRepo handles user CRUD against PostgreSQL.
type UserRepo struct {
	db *DB
}

// NewUserRepo creates a UserRepo backed by db.
func NewUserRepo(db *DB) *UserRepo { return &UserRepo{db: db} }

func normalizeKind(kind string) string {
	k := strings.TrimSpace(strings.ToLower(kind))
	if k == "" {
		return "vless"
	}
	return k
}

// Add inserts a VLESS user; historical kinds are read-only.
func (r *UserRepo) Add(ctx context.Context, kind, name string) (auth.User, error) {
	if normalizeKind(kind) != "vless" {
		return auth.User{}, auth.ErrInvalidUserKind
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return auth.User{}, auth.ErrEmptyUserName
	}
	id := uuid.New()
	u := auth.User{UUID: (&id).String(), Name: name, Kind: "vless", IsActive: true}
	pgUUID, err := toPGUUID(u.UUID)
	if err != nil {
		return auth.User{}, err
	}
	err = r.db.orm.WithContext(ctx).Table("users").Create(map[string]any{"uuid": fromPGUUID(pgUUID), "name": u.Name, "kind": "vless"}).Error
	return u, err
}

// Rename updates the display name of a user.
func (r *UserRepo) Rename(ctx context.Context, id, name string) (auth.User, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return auth.User{}, auth.ErrEmptyUserName
	}
	pgUUID, err := toPGUUID(id)
	if err != nil {
		return auth.User{}, err
	}
	var row userRow
	result := r.db.orm.WithContext(ctx).Model(&row).Clauses(clause.Returning{}).Where("uuid = ?", fromPGUUID(pgUUID)).Update("name", name)
	err = result.Error
	if err == nil && result.RowsAffected == 0 {
		err = pgx.ErrNoRows
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	return row.user(), err
}

// Remove soft-deletes a user by UUID (sets is_active=false).
func (r *UserRepo) Remove(ctx context.Context, id string) error {
	pgUUID, err := toPGUUID(id)
	if err != nil {
		return err
	}
	result := r.db.orm.WithContext(ctx).Table("users").Where("uuid = ? AND is_active", fromPGUUID(pgUUID)).Updates(map[string]any{"is_active": false, "disabled_at": gorm.Expr("NOW()")})
	affected, err := result.RowsAffected, result.Error
	if err != nil {
		return err
	}
	if affected == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}

// Purge permanently deletes a user row. ON DELETE CASCADE on referencing tables
// (traffic_stats, monthly_traffic, notifications, user_ip_observations,
// user_leak_signals) wipes related history.
func (r *UserRepo) Purge(ctx context.Context, id string) error {
	var row userRow
	if err := cloudLookupError(r.db.orm.WithContext(ctx).Select("enrollment_source").Where("uuid = ?", id).Take(&row).Error); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.ErrUserNotFound
		}
		return err
	}
	if row.EnrollmentSource != nil {
		return errors.New("enrolled accounts must be disabled, not purged")
	}

	pgUUID, err := toPGUUID(id)
	if err != nil {
		return err
	}
	result := r.db.orm.WithContext(ctx).Where("uuid = ?", fromPGUUID(pgUUID)).Delete(&userRow{})
	affected, err := result.RowsAffected, result.Error
	if err != nil {
		return err
	}
	if affected == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}

// Enable restores a disabled user by UUID.
func (r *UserRepo) Enable(ctx context.Context, id string) error {
	u, ok, err := r.Lookup(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return auth.ErrUserNotFound
	}
	if u.Kind != "vless" {
		return auth.ErrUnsupportedForKind
	}
	pgUUID, err := toPGUUID(id)
	if err != nil {
		return err
	}
	result := r.db.orm.WithContext(ctx).Table("users").Where("uuid = ? AND kind = ?", fromPGUUID(pgUUID), "vless").Updates(map[string]any{"is_active": true, "disabled_at": nil})
	affected, err := result.RowsAffected, result.Error
	if err != nil {
		return err
	}
	if affected == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}

// SetPreferredExit stores the user's preferred exit node. nil means Auto.
func (r *UserRepo) SetPreferredExit(ctx context.Context, id string, exitID *string) (auth.User, error) {
	pgUUID, err := toPGUUID(id)
	if err != nil {
		return auth.User{}, err
	}
	pgExitID, err := toPGUUIDPtr(exitID)
	if err != nil {
		return auth.User{}, err
	}
	var row userRow
	result := r.db.orm.WithContext(ctx).Model(&row).Clauses(clause.Returning{}).Where("uuid = ? AND is_active", fromPGUUID(pgUUID)).Update("preferred_exit_id", ptrFromPGUUID(pgExitID))
	err = result.Error
	if err == nil && result.RowsAffected == 0 {
		err = pgx.ErrNoRows
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	if err != nil {
		return auth.User{}, err
	}
	return row.user(), nil
}

// RotateUUID replaces a user's UUID and updates references in related tables.
func (r *UserRepo) RotateUUID(ctx context.Context, id string) (string, error) {
	u, ok, err := r.Lookup(ctx, id)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", auth.ErrUserNotFound
	}
	if u.Kind != "vless" {
		return "", auth.ErrUnsupportedForKind
	}

	newID := uuid.New()
	newUUID := (&newID).String()

	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365007)`); err != nil {
		return "", err
	}
	result, err := r.rotateUUIDTx(ctx, tx, id, newUUID)
	if err != nil {
		return "", err
	}
	return result, tx.Commit(ctx)
}

func (r *UserRepo) rotateUUIDTx(ctx context.Context, tx pgx.Tx, id, newUUID string) (string, error) {
	qtx := r.db.Queries.WithTx(tx)
	oldPGUUID := mustPGUUID(id)
	newPGUUID := mustPGUUID(newUUID)
	if err := qtx.CloneUserForUUIDRotation(ctx, sqlc.CloneUserForUUIDRotationParams{Uuid: oldPGUUID, Uuid_2: newPGUUID}); err != nil {
		return "", err
	}
	if err := qtx.MoveTrafficStatsUserUUID(ctx, sqlc.MoveTrafficStatsUserUUIDParams{UserUuid: oldPGUUID, UserUuid_2: newPGUUID}); err != nil {
		return "", err
	}
	if err := qtx.MoveUserExitQuotasUUID(ctx, sqlc.MoveUserExitQuotasUUIDParams{UserUuid: oldPGUUID, UserUuid_2: newPGUUID}); err != nil {
		return "", err
	}
	if err := qtx.MoveDailyRouteTrafficUserUUID(ctx, sqlc.MoveDailyRouteTrafficUserUUIDParams{UserUuid: oldPGUUID, UserUuid_2: newPGUUID}); err != nil {
		return "", err
	}
	if err := qtx.MoveMonthlyTrafficUserUUID(ctx, sqlc.MoveMonthlyTrafficUserUUIDParams{UserUuid: oldPGUUID, UserUuid_2: newPGUUID}); err != nil {
		return "", err
	}
	if err := qtx.MoveNotificationsUserUUID(ctx, sqlc.MoveNotificationsUserUUIDParams{UserUuid: oldPGUUID, UserUuid_2: newPGUUID}); err != nil {
		return "", err
	}
	if err := qtx.MoveIPObservationsUserUUID(ctx, sqlc.MoveIPObservationsUserUUIDParams{UserUuid: oldPGUUID, UserUuid_2: newPGUUID}); err != nil {
		return "", err
	}
	if err := qtx.MoveLeakSignalsUserUUID(ctx, sqlc.MoveLeakSignalsUserUUIDParams{UserUuid: oldPGUUID, UserUuid_2: newPGUUID}); err != nil {
		return "", err
	}
	if _, err := qtx.DeleteUser(ctx, oldPGUUID); err != nil {
		return "", err
	}

	return newUUID, nil
}

// List returns all active users ordered by creation time.
func (r *UserRepo) List(ctx context.Context) ([]auth.User, error) {
	rows := []userRow{}
	err := r.db.orm.WithContext(ctx).Where("is_active").Order("created_at").Find(&rows).Error
	if err != nil {
		return nil, err
	}
	users := make([]auth.User, 0, len(rows))
	for _, row := range rows {
		users = append(users, row.user())
	}
	return users, nil
}

// ListAll returns active and disabled users ordered by creation time.
func (r *UserRepo) ListAll(ctx context.Context) ([]auth.User, error) {
	rows := []userRow{}
	err := r.db.orm.WithContext(ctx).Order("created_at").Find(&rows).Error
	if err != nil {
		return nil, err
	}
	users := make([]auth.User, 0, len(rows))
	for _, row := range rows {
		users = append(users, row.user())
	}
	users, err = r.attachServices(ctx, users)
	if err != nil {
		return nil, err
	}
	return NewRouteRepo(r.db).Attach(ctx, users)
}

// Lookup returns a single user by UUID (active or disabled).
func (r *UserRepo) Lookup(ctx context.Context, id string) (auth.User, bool, error) {
	pgUUID, err := toPGUUID(id)
	if err != nil {
		return auth.User{}, false, err
	}
	var row userRow
	err = cloudLookupError(r.db.orm.WithContext(ctx).Where("uuid = ?", fromPGUUID(pgUUID)).Take(&row).Error)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, false, nil
	}
	if err != nil {
		return auth.User{}, false, err
	}
	return row.user(), true, nil
}
