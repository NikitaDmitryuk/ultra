package db

import (
	"context"
	"errors"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/db/sqlc"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xtls/xray-core/common/uuid"
)

// UserRepo handles user CRUD against PostgreSQL.
type UserRepo struct {
	db *DB
}

// NewUserRepo creates a UserRepo backed by db.
func NewUserRepo(db *DB) *UserRepo { return &UserRepo{db: db} }

func authUserFromFields(
	uuid pgtype.UUID,
	name, kind string,
	isActive bool,
	disabledAt pgtype.Timestamptz,
	socksUsername, socksPassword pgtype.Text,
	socksPort pgtype.Int4,
	leakPolicy string,
	leakMaxConcurrent, leakMaxUnique pgtype.Int4,
	preferredExitID pgtype.UUID,
) auth.User {
	u := auth.User{
		UUID:            fromPGUUID(uuid),
		Name:            name,
		Kind:            kind,
		IsActive:        isActive,
		DisabledAt:      ptrFromPGTime(disabledAt),
		PreferredExitID: ptrFromPGUUID(preferredExitID),
	}
	u.SocksUsername = fromPGText(socksUsername)
	u.SocksPassword = fromPGText(socksPassword)
	u.SocksPort = ptrFromPGInt4(socksPort)
	u.LeakPolicy = leakPolicy
	u.LeakMaxConcurrentIPs = ptrFromPGInt4(leakMaxConcurrent)
	u.LeakMaxUniqueIPs24h = ptrFromPGInt4(leakMaxUnique)
	if u.Kind == "" {
		u.Kind = "vless"
	}
	return u
}

func authUserFromGet(row sqlc.GetUserRow) auth.User {
	return authUserFromFields(
		row.Uuid,
		row.Name,
		row.Kind,
		row.IsActive,
		row.DisabledAt,
		row.SocksUsername,
		row.SocksPassword,
		row.SocksPort,
		row.LeakPolicy,
		row.LeakMaxConcurrentIps,
		row.LeakMaxUniqueIps24h,
		row.PreferredExitID,
	)
}

func authUserFromListActive(row sqlc.ListActiveUsersRow) auth.User {
	return authUserFromFields(
		row.Uuid,
		row.Name,
		row.Kind,
		row.IsActive,
		row.DisabledAt,
		row.SocksUsername,
		row.SocksPassword,
		row.SocksPort,
		row.LeakPolicy,
		row.LeakMaxConcurrentIps,
		row.LeakMaxUniqueIps24h,
		row.PreferredExitID,
	)
}

func authUserFromListAll(row sqlc.ListAllUsersRow) auth.User {
	return authUserFromFields(
		row.Uuid,
		row.Name,
		row.Kind,
		row.IsActive,
		row.DisabledAt,
		row.SocksUsername,
		row.SocksPassword,
		row.SocksPort,
		row.LeakPolicy,
		row.LeakMaxConcurrentIps,
		row.LeakMaxUniqueIps24h,
		row.PreferredExitID,
	)
}

func authUserFromRename(row sqlc.RenameUserRow) auth.User {
	return authUserFromFields(
		row.Uuid,
		row.Name,
		row.Kind,
		row.IsActive,
		row.DisabledAt,
		row.SocksUsername,
		row.SocksPassword,
		row.SocksPort,
		row.LeakPolicy,
		row.LeakMaxConcurrentIps,
		row.LeakMaxUniqueIps24h,
		row.PreferredExitID,
	)
}

func authUserFromSetPreferredExit(row sqlc.SetUserPreferredExitRow) auth.User {
	return authUserFromFields(
		row.Uuid,
		row.Name,
		row.Kind,
		row.IsActive,
		row.DisabledAt,
		row.SocksUsername,
		row.SocksPassword,
		row.SocksPort,
		row.LeakPolicy,
		row.LeakMaxConcurrentIps,
		row.LeakMaxUniqueIps24h,
		row.PreferredExitID,
	)
}

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
	err = r.db.Queries.InsertVlessUser(ctx, sqlc.InsertVlessUserParams{Uuid: pgUUID, Name: u.Name})
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
	row, err := r.db.Queries.RenameUser(ctx, sqlc.RenameUserParams{Name: name, Uuid: pgUUID})
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	return authUserFromRename(row), err
}

// Remove soft-deletes a user by UUID (sets is_active=false).
func (r *UserRepo) Remove(ctx context.Context, id string) error {
	pgUUID, err := toPGUUID(id)
	if err != nil {
		return err
	}
	affected, err := r.db.Queries.DisableUser(ctx, pgUUID)
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
	var enrolled bool
	if err := r.db.Pool.QueryRow(ctx, `SELECT enrollment_source IS NOT NULL FROM users WHERE uuid=$1`, id).Scan(&enrolled); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return auth.ErrUserNotFound
		}
		return err
	}
	if enrolled {
		return errors.New("enrolled accounts must be disabled, not purged")
	}

	pgUUID, err := toPGUUID(id)
	if err != nil {
		return err
	}
	affected, err := r.db.Queries.DeleteUser(ctx, pgUUID)
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
	affected, err := r.db.Queries.EnableUser(ctx, pgUUID)
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
	row, err := r.db.Queries.SetUserPreferredExit(ctx, sqlc.SetUserPreferredExitParams{
		Uuid:            pgUUID,
		PreferredExitID: pgExitID,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	if err != nil {
		return auth.User{}, err
	}
	return authUserFromSetPreferredExit(row), nil
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
	rows, err := r.db.Queries.ListActiveUsers(ctx)
	if err != nil {
		return nil, err
	}
	users := make([]auth.User, 0, len(rows))
	for _, row := range rows {
		users = append(users, authUserFromListActive(row))
	}
	return users, nil
}

// ListAll returns active and disabled users ordered by creation time.
func (r *UserRepo) ListAll(ctx context.Context) ([]auth.User, error) {
	rows, err := r.db.Queries.ListAllUsers(ctx)
	if err != nil {
		return nil, err
	}
	users := make([]auth.User, 0, len(rows))
	for _, row := range rows {
		users = append(users, authUserFromListAll(row))
	}
	return NewRouteRepo(r.db).Attach(ctx, users)
}

// Lookup returns a single user by UUID (active or disabled).
func (r *UserRepo) Lookup(ctx context.Context, id string) (auth.User, bool, error) {
	pgUUID, err := toPGUUID(id)
	if err != nil {
		return auth.User{}, false, err
	}
	row, err := r.db.Queries.GetUser(ctx, pgUUID)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, false, nil
	}
	if err != nil {
		return auth.User{}, false, err
	}
	return authUserFromGet(row), true, nil
}
