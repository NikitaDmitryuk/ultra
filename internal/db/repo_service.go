package db

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// EnsureMonitorAccess maintains one accounting owner. Recreating a deleted
// credential must reuse that owner so outstanding charges cannot be escaped.
func (r *UserRepo) EnsureMonitorAccess(ctx context.Context, targets []string) (auth.User, error) {
	if len(targets) == 0 {
		return auth.User{}, errors.New("monitor targets required")
	}
	for _, target := range targets {
		u, e := url.Parse(target)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" ||
			(u.Port() != "" && u.Port() != "443") ||
			strings.ContainsAny(u.Hostname(), "* ,\n\r") {
			return auth.User{}, errors.New("invalid monitor HTTPS target")
		}
	}
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return auth.User{}, e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365024)`); e != nil {
		return auth.User{}, e
	}
	var owner string
	e = tx.QueryRow(ctx, `SELECT account_id::text FROM service_access WHERE name='monitor'`).Scan(&owner)
	if errors.Is(e, pgx.ErrNoRows) {
		owner = uuid.NewString()
		if _, e = tx.Exec(ctx, `INSERT INTO traffic_accounts(account_id) VALUES($1)`, owner); e != nil {
			return auth.User{}, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO service_access(name,account_id,targets) VALUES('monitor',$1,$2)`, owner, targets); e != nil {
			return auth.User{}, e
		}
	} else if e != nil {
		return auth.User{}, e
	}
	var id string
	e = tx.QueryRow(ctx, `SELECT uuid::text FROM users WHERE account_id=$1`, owner).Scan(&id)
	if errors.Is(e, pgx.ErrNoRows) {
		id = uuid.NewString()
		_, e = tx.Exec(ctx, `INSERT INTO users(uuid,account_id,name,kind) VALUES($1,$2,'Infrastructure monitor','vless')`, id, owner)
	}
	if e != nil {
		return auth.User{}, e
	}
	// Explicitly disabled service access remains disabled until the operator enables it.
	var active bool
	if e = tx.QueryRow(ctx, `SELECT is_active FROM users WHERE uuid=$1`, id).Scan(&active); e != nil {
		return auth.User{}, e
	}
	if !active {
		return auth.User{}, errors.New("monitor access disabled")
	}
	if _, e = tx.Exec(ctx, `UPDATE service_access SET targets=$1 WHERE name='monitor'`, targets); e != nil {
		return auth.User{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return auth.User{}, e
	}
	return auth.User{
		UUID:           id,
		AccountID:      owner,
		Name:           "Infrastructure monitor",
		Kind:           "vless",
		IsActive:       true,
		ServiceTargets: targets,
	}, nil
}

func (r *UserRepo) attachServices(ctx context.Context, users []auth.User) ([]auth.User, error) {
	var rows []struct {
		AccountID string
		Targets   json.RawMessage `gorm:"type:json"`
	}
	if e := r.db.orm.WithContext(ctx).Table("service_access").Select("account_id, array_to_json(targets) AS targets").Find(&rows).Error; e != nil {
		return nil, e
	}
	targets := map[string][]string{}
	for _, row := range rows {
		var ts []string
		if e := json.Unmarshal(row.Targets, &ts); e != nil {
			return nil, e
		}
		targets[row.AccountID] = ts
	}

	for i := range users {
		users[i].ServiceTargets = targets[users[i].AccountID]
	}
	return users, nil
}

// EnsureInitialMonitorAdmin accepts an explicit owner at first installation only.
func (r *UserRepo) EnsureInitialMonitorAdmin(ctx context.Context, id int64) error {
	if id <= 0 {
		return errors.New("positive initial admin id required")
	}
	tx, e := r.db.Pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365024)`); e != nil {
		return e
	}
	var any, exists bool
	if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM bot_admins),EXISTS(SELECT 1 FROM bot_admins WHERE telegram_id=$1)`, id).Scan(&any, &exists); e != nil {
		return e
	}
	if any && !exists {
		return errors.New("initial admin conflicts with existing owner")
	}
	if !any {
		if _, e = tx.Exec(ctx, `INSERT INTO bot_admins(telegram_id,telegram_name) VALUES($1,'Initial operator')`, id); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
