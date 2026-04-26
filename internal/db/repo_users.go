package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/jackc/pgx/v5"
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

const userSelectCols = `uuid, name, kind, is_active, disabled_at,
		socks_username, socks_password, socks_port,
		leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h`

func scanUser(row interface{ Scan(dest ...any) error }) (auth.User, error) {
	var u auth.User
	var su, spw sql.NullString
	var sport sql.NullInt32
	err := row.Scan(
		&u.UUID, &u.Name, &u.Kind, &u.IsActive, &u.DisabledAt,
		&su, &spw, &sport,
		&u.LeakPolicy, &u.LeakMaxConcurrentIPs, &u.LeakMaxUniqueIPs24h,
	)
	if err != nil {
		return auth.User{}, err
	}
	if su.Valid {
		u.SocksUsername = su.String
	}
	if spw.Valid {
		u.SocksPassword = spw.String
	}
	if sport.Valid {
		v := int(sport.Int32)
		u.SocksPort = &v
	}
	if u.Kind == "" {
		u.Kind = "vless"
	}
	return u, nil
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
		var exists bool
		if err := r.db.Pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE socks_port=$1)`, p,
		).Scan(&exists); err != nil {
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
		_, err := r.db.Pool.Exec(ctx,
			`INSERT INTO users(uuid, name, kind) VALUES($1, $2, 'vless')`,
			u.UUID, u.Name,
		)
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
		_, err = r.db.Pool.Exec(ctx,
			`INSERT INTO users(uuid, name, kind, socks_username, socks_password, socks_port)
			 VALUES($1, $2, 'socks5', $3, $4, $5)`,
			u.UUID, u.Name, u.SocksUsername, u.SocksPassword, port,
		)
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
	row := r.db.Pool.QueryRow(ctx,
		`UPDATE users SET socks_password=$1 WHERE uuid=$2 AND kind='socks5' AND is_active=true
		 RETURNING `+userSelectCols,
		pass, id,
	)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	if err != nil {
		return auth.User{}, err
	}
	return u, nil
}

// Rename updates the display name of a user.
func (r *UserRepo) Rename(ctx context.Context, id, name string) (auth.User, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return auth.User{}, auth.ErrEmptyUserName
	}
	row := r.db.Pool.QueryRow(ctx,
		`UPDATE users SET name=$1 WHERE uuid=$2
		 RETURNING `+userSelectCols,
		name, id,
	)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	return u, err
}

// Remove soft-deletes a user by UUID (sets is_active=false).
func (r *UserRepo) Remove(ctx context.Context, id string) error {
	tag, err := r.db.Pool.Exec(ctx,
		"UPDATE users SET is_active=false, disabled_at=NOW() WHERE uuid=$1 AND is_active=true", id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}

// Purge permanently deletes a user row. ON DELETE CASCADE on referencing tables
// (traffic_stats, monthly_traffic, notifications, user_ip_observations,
// user_leak_signals) wipes related history.
func (r *UserRepo) Purge(ctx context.Context, id string) error {
	tag, err := r.db.Pool.Exec(ctx, "DELETE FROM users WHERE uuid=$1", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}

// Enable restores a disabled user by UUID.
func (r *UserRepo) Enable(ctx context.Context, id string) error {
	tag, err := r.db.Pool.Exec(ctx,
		"UPDATE users SET is_active=true, disabled_at=NULL WHERE uuid=$1", id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
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

	if _, err := tx.Exec(ctx, `
		INSERT INTO users(
			uuid, name, telegram_id, telegram_username, created_at, is_active, disabled_at,
			leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h,
			kind, socks_username, socks_password, socks_port
		)
		SELECT
			$2, name, telegram_id, telegram_username, created_at, is_active, disabled_at,
			leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h,
			kind, socks_username, socks_password, socks_port
		FROM users WHERE uuid=$1
	`, id, newUUID); err != nil {
		return "", err
	}

	updateTables := []string{
		"UPDATE traffic_stats SET user_uuid=$2 WHERE user_uuid=$1",
		"UPDATE monthly_traffic SET user_uuid=$2 WHERE user_uuid=$1",
		"UPDATE notifications SET user_uuid=$2 WHERE user_uuid=$1",
		"UPDATE user_ip_observations SET user_uuid=$2 WHERE user_uuid=$1",
		"UPDATE user_leak_signals SET user_uuid=$2 WHERE user_uuid=$1",
	}
	for _, q := range updateTables {
		if _, err := tx.Exec(ctx, q, id, newUUID); err != nil {
			return "", err
		}
	}
	if _, err := tx.Exec(ctx, "DELETE FROM users WHERE uuid=$1", id); err != nil {
		return "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return newUUID, nil
}

// List returns all active users ordered by creation time.
func (r *UserRepo) List(ctx context.Context) ([]auth.User, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT `+userSelectCols+`
		 FROM users WHERE is_active=true ORDER BY created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []auth.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// ListAll returns active and disabled users ordered by creation time.
func (r *UserRepo) ListAll(ctx context.Context) ([]auth.User, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT `+userSelectCols+`
		 FROM users ORDER BY created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []auth.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// Lookup returns a single user by UUID (active or disabled).
func (r *UserRepo) Lookup(ctx context.Context, id string) (auth.User, bool, error) {
	row := r.db.Pool.QueryRow(ctx,
		`SELECT `+userSelectCols+` FROM users WHERE uuid=$1`, id,
	)
	u, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, false, nil
	}
	if err != nil {
		return auth.User{}, false, err
	}
	return u, true, nil
}
