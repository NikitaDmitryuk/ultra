package db

import (
	"context"
	"errors"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/jackc/pgx/v5"
	"github.com/xtls/xray-core/common/uuid"
)

// UserRepo handles user CRUD against PostgreSQL.
type UserRepo struct {
	db *DB
}

// NewUserRepo creates a UserRepo backed by db.
func NewUserRepo(db *DB) *UserRepo { return &UserRepo{db: db} }

// Add inserts a new user with a fresh UUID and returns it.
func (r *UserRepo) Add(ctx context.Context, name string) (auth.User, error) {
	id := uuid.New()
	u := auth.User{
		UUID:     (&id).String(),
		Name:     strings.TrimSpace(name),
		IsActive: true,
	}
	_, err := r.db.Pool.Exec(ctx,
		"INSERT INTO users(uuid, name) VALUES($1, $2)",
		u.UUID, u.Name,
	)
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
	var u auth.User
	err := r.db.Pool.QueryRow(ctx,
		`UPDATE users SET name=$1 WHERE uuid=$2
		 RETURNING uuid, name, is_active, disabled_at,
		           leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h`,
		name, id,
	).Scan(
		&u.UUID, &u.Name, &u.IsActive, &u.DisabledAt,
		&u.LeakPolicy, &u.LeakMaxConcurrentIPs, &u.LeakMaxUniqueIPs24h,
	)
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
	newID := uuid.New()
	newUUID := (&newID).String()

	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	var exists bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE uuid=$1)", id).Scan(&exists); err != nil {
		return "", err
	}
	if !exists {
		return "", auth.ErrUserNotFound
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO users(
			uuid, name, telegram_id, telegram_username, created_at, is_active, disabled_at,
			leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h
		)
		SELECT
			$2, name, telegram_id, telegram_username, created_at, is_active, disabled_at,
			leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h
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
		`SELECT uuid, name, is_active, disabled_at,
		        leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h
		 FROM users WHERE is_active=true ORDER BY created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []auth.User
	for rows.Next() {
		var u auth.User
		if err := rows.Scan(
			&u.UUID, &u.Name, &u.IsActive, &u.DisabledAt,
			&u.LeakPolicy, &u.LeakMaxConcurrentIPs, &u.LeakMaxUniqueIPs24h,
		); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// ListAll returns active and disabled users ordered by creation time.
func (r *UserRepo) ListAll(ctx context.Context) ([]auth.User, error) {
	rows, err := r.db.Pool.Query(ctx,
		`SELECT uuid, name, is_active, disabled_at,
		        leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h
		 FROM users ORDER BY created_at`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []auth.User
	for rows.Next() {
		var u auth.User
		if err := rows.Scan(
			&u.UUID, &u.Name, &u.IsActive, &u.DisabledAt,
			&u.LeakPolicy, &u.LeakMaxConcurrentIPs, &u.LeakMaxUniqueIPs24h,
		); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// Lookup returns a single user by UUID (active or disabled).
func (r *UserRepo) Lookup(ctx context.Context, id string) (auth.User, bool, error) {
	var u auth.User
	err := r.db.Pool.QueryRow(ctx,
		`SELECT uuid, name, is_active, disabled_at,
		        leak_policy, leak_max_concurrent_ips, leak_max_unique_ips_24h
		 FROM users WHERE uuid=$1`,
		id,
	).Scan(
		&u.UUID, &u.Name, &u.IsActive, &u.DisabledAt,
		&u.LeakPolicy, &u.LeakMaxConcurrentIPs, &u.LeakMaxUniqueIPs24h,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, false, nil
	}
	if err != nil {
		return auth.User{}, false, err
	}
	return u, true, nil
}
