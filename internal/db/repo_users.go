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
	u := auth.User{UUID: (&id).String(), Name: name}
	_, err := r.db.Pool.Exec(ctx,
		"INSERT INTO users(uuid, name) VALUES($1, $2)",
		u.UUID, u.Name,
	)
	if err != nil {
		return auth.User{}, err
	}
	return u, nil
}

// Rename updates the display name of an active user.
func (r *UserRepo) Rename(ctx context.Context, id, name string) (auth.User, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return auth.User{}, auth.ErrEmptyUserName
	}
	var u auth.User
	err := r.db.Pool.QueryRow(ctx,
		`UPDATE users SET name=$1 WHERE uuid=$2 AND is_active=true
		 RETURNING uuid, name`,
		name, id,
	).Scan(&u.UUID, &u.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, auth.ErrUserNotFound
	}
	return u, err
}

// Remove soft-deletes a user by UUID (sets is_active=false).
func (r *UserRepo) Remove(ctx context.Context, id string) error {
	tag, err := r.db.Pool.Exec(ctx,
		"UPDATE users SET is_active=false WHERE uuid=$1 AND is_active=true", id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return auth.ErrUserNotFound
	}
	return nil
}

// List returns all active users ordered by creation time.
func (r *UserRepo) List(ctx context.Context) ([]auth.User, error) {
	rows, err := r.db.Pool.Query(ctx,
		"SELECT uuid, name FROM users WHERE is_active=true ORDER BY created_at",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []auth.User
	for rows.Next() {
		var u auth.User
		if err := rows.Scan(&u.UUID, &u.Name); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// Lookup returns a single active user by UUID.
func (r *UserRepo) Lookup(ctx context.Context, id string) (auth.User, bool, error) {
	var u auth.User
	err := r.db.Pool.QueryRow(ctx,
		"SELECT uuid, name FROM users WHERE uuid=$1 AND is_active=true", id,
	).Scan(&u.UUID, &u.Name)
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.User{}, false, nil
	}
	if err != nil {
		return auth.User{}, false, err
	}
	return u, true, nil
}
