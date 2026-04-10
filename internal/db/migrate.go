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
