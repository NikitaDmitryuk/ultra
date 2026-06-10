package db

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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

	socksPortStart  int
	socksPortEnd    int
	socksLegacyPort int
}

// NewUserRepo creates a UserRepo backed by db.
func NewUserRepo(db *DB) *UserRepo {
	return &UserRepo{
		db:             db,
		socksPortStart: 10810,
		socksPortEnd:   10899,
	}
}

// SetSOCKS5BridgePorts configures TCP port pool for kind=socks5 users. legacyPort (global inbound)
// is never auto-assigned to a new SOCKS5 client. Pass 0 when global SOCKS5 is disabled.
func (r *UserRepo) SetSOCKS5BridgePorts(rangeStart, rangeEnd, legacyPort int) {
	if rangeStart > 0 {
		r.socksPortStart = rangeStart
	}
	if rangeEnd > 0 {
		r.socksPortEnd = rangeEnd
	}
	r.socksLegacyPort = legacyPort
}

func authUserFromFields(
	uuid pgtype.UUID,
	name, kind string,
	isActive bool,
	disabledAt pgtype.Timestamptz,
	socksUsername, socksPassword pgtype.Text,
	socksPort pgtype.Int4,
	leakPolicy string,
	leakMaxConcurrent, leakMaxUnique pgtype.Int4,
) auth.User {
	u := auth.User{
		UUID:       fromPGUUID(uuid),
		Name:       name,
		Kind:       kind,
		IsActive:   isActive,
		DisabledAt: ptrFromPGTime(disabledAt),
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
	return authUserFromFields(row.Uuid, row.Name, row.Kind, row.IsActive, row.DisabledAt, row.SocksUsername, row.SocksPassword, row.SocksPort, row.LeakPolicy, row.LeakMaxConcurrentIps, row.LeakMaxUniqueIps24h)
}

func authUserFromListActive(row sqlc.ListActiveUsersRow) auth.User {
	return authUserFromFields(row.Uuid, row.Name, row.Kind, row.IsActive, row.DisabledAt, row.SocksUsername, row.SocksPassword, row.SocksPort, row.LeakPolicy, row.LeakMaxConcurrentIps, row.LeakMaxUniqueIps24h)
}

func authUserFromListAll(row sqlc.ListAllUsersRow) auth.User {
	return authUserFromFields(row.Uuid, row.Name, row.Kind, row.IsActive, row.DisabledAt, row.SocksUsername, row.SocksPassword, row.SocksPort, row.LeakPolicy, row.LeakMaxConcurrentIps, row.LeakMaxUniqueIps24h)
}

func authUserFromRename(row sqlc.RenameUserRow) auth.User {
	return authUserFromFields(row.Uuid, row.Name, row.Kind, row.IsActive, row.DisabledAt, row.SocksUsername, row.SocksPassword, row.SocksPort, row.LeakPolicy, row.LeakMaxConcurrentIps, row.LeakMaxUniqueIps24h)
}

func authUserFromRotateSocks(row sqlc.RotateSocksPasswordRow) auth.User {
	return authUserFromFields(row.Uuid, row.Name, row.Kind, row.IsActive, row.DisabledAt, row.SocksUsername, row.SocksPassword, row.SocksPort, row.LeakPolicy, row.LeakMaxConcurrentIps, row.LeakMaxUniqueIps24h)
}

func randomSocksPassword() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func normalizeKind(kind string) string {
	k := strings.TrimSpace(strings.ToLower(kind))
	if k == "" {
		return "vless"
	}
	return k
}

func (r *UserRepo) nextSocksPort(ctx context.Context) (int, error) {
	for p := r.socksPortStart; p <= r.socksPortEnd; p++ {
		if r.socksLegacyPort != 0 && p == r.socksLegacyPort {
			continue
		}
		exists, err := r.db.Queries.UserSocksPortExists(ctx, toPGInt4(int32(p)))
		if err != nil {
			return 0, err
		}
		if !exists {
			return p, nil
		}
	}
	return 0, auth.ErrSocksPortsExhausted
}

// Add inserts a new user. kind is "vless" (default) or "socks5".
func (r *UserRepo) Add(ctx context.Context, kind, name string) (auth.User, error) {
	kind = normalizeKind(kind)
	if kind != "vless" && kind != "socks5" {
		return auth.User{}, auth.ErrInvalidUserKind
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return auth.User{}, auth.ErrEmptyUserName
	}

	id := uuid.New()
	uuidStr := (&id).String()

	switch kind {
	case "vless":
		u := auth.User{
			UUID:     uuidStr,
			Name:     name,
			Kind:     "vless",
			IsActive: true,
		}
		pgUUID, err := toPGUUID(u.UUID)
		if err != nil {
			return auth.User{}, err
		}
		err = r.db.Queries.InsertVlessUser(ctx, sqlc.InsertVlessUserParams{Uuid: pgUUID, Name: u.Name})
		if err != nil {
			return auth.User{}, err
		}
		return u, nil
	case "socks5":
		pass, err := randomSocksPassword()
		if err != nil {
			return auth.User{}, err
		}
		port, err := r.nextSocksPort(ctx)
		if err != nil {
			return auth.User{}, err
		}
		u := auth.User{
			UUID:          uuidStr,
			Name:          name,
			Kind:          "socks5",
			IsActive:      true,
			SocksUsername: uuidStr,
			SocksPassword: pass,
			SocksPort:     &port,
		}
		err = r.db.Queries.InsertSocksUser(ctx, sqlc.InsertSocksUserParams{
			Uuid:          mustPGUUID(u.UUID),
			Name:          u.Name,
			SocksUsername: toPGText(u.SocksUsername),
			SocksPassword: toPGText(u.SocksPassword),
			SocksPort:     toPGInt4(int32(port)),
		})
		if err != nil {
			return auth.User{}, err
		}
		return u, nil
	default:
		return auth.User{}, auth.ErrInvalidUserKind
	}
}

// RotateSocksPassword replaces the SOCKS5 password for a socks5 user.
func (r *UserRepo) RotateSocksPassword(ctx context.Context, id string) (auth.User, error) {
	pass, err := randomSocksPassword()
	if err != nil {
		return auth.User{}, err
	}
	pgUUID, err := toPGUUID(id)
	if err != nil {
		return auth.User{}, err
	}
	row, err := r.db.Queries.RotateSocksPassword(ctx, sqlc.RotateSocksPasswordParams{SocksPassword: toPGText(pass), Uuid: pgUUID})
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	if err != nil {
		return auth.User{}, err
	}
	return authUserFromRotateSocks(row), nil
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

// RotateUUID replaces a user's UUID and updates references in related tables.
func (r *UserRepo) RotateUUID(ctx context.Context, id string) (string, error) {
	u, ok, err := r.Lookup(ctx, id)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", auth.ErrUserNotFound
	}
	if u.Kind == "socks5" {
		return "", auth.ErrUnsupportedForKind
	}

	newID := uuid.New()
	newUUID := (&newID).String()

	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	qtx := r.db.Queries.WithTx(tx)
	oldPGUUID := mustPGUUID(id)
	newPGUUID := mustPGUUID(newUUID)
	if err := qtx.CloneUserForUUIDRotation(ctx, sqlc.CloneUserForUUIDRotationParams{Uuid: oldPGUUID, Uuid_2: newPGUUID}); err != nil {
		return "", err
	}
	if err := qtx.MoveTrafficStatsUserUUID(ctx, sqlc.MoveTrafficStatsUserUUIDParams{UserUuid: oldPGUUID, UserUuid_2: newPGUUID}); err != nil {
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

	if err := tx.Commit(ctx); err != nil {
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
	return users, nil
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
