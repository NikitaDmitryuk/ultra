package db

import (
	"context"
	_ "embed"
	"fmt"
)

//go:embed migrations/001_initial.sql
var migration001 string

//go:embed migrations/002_bot_admins.sql
var migration002 string

//go:embed migrations/003_users_admin_meta.sql
var migration003 string

//go:embed migrations/004_ip_observations.sql
var migration004 string

//go:embed migrations/005_admin_audit.sql
var migration005 string

//go:embed migrations/006_drop_user_note.sql
var migration006 string

//go:embed migrations/007_drop_admin_audit.sql
var migration007 string

//go:embed migrations/008_drop_legacy_tables.sql
var migration008 string

//go:embed migrations/009_notifications_user_cascade.sql
var migration009 string

//go:embed migrations/010_leak_global_only.sql
var migration010 string

//go:embed migrations/011_users_proxy_kind.sql
var migration011 string

func (d *DB) migrate(ctx context.Context) error {
	_, err := d.Pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    INT         PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	if err != nil {
		return fmt.Errorf("create migrations table: %w", err)
	}

	type migration struct {
		version int
		sql     string
	}
	migrations := []migration{
		{1, migration001},
		{2, migration002},
		{3, migration003},
		{4, migration004},
		{5, migration005},
		{6, migration006},
		{7, migration007},
		{8, migration008},
		{9, migration009},
		{10, migration010},
		{11, migration011},
	}

	for _, m := range migrations {
		var applied bool
		if err := d.Pool.QueryRow(ctx,
			"SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)", m.version,
		).Scan(&applied); err != nil {
			return fmt.Errorf("check migration %d: %w", m.version, err)
		}
		if applied {
			continue
		}
		if _, err := d.Pool.Exec(ctx, m.sql); err != nil {
			return fmt.Errorf("apply migration %d: %w", m.version, err)
		}
		if _, err := d.Pool.Exec(ctx,
			"INSERT INTO schema_migrations(version) VALUES($1)", m.version,
		); err != nil {
			return fmt.Errorf("record migration %d: %w", m.version, err)
		}
	}
	return nil
}
