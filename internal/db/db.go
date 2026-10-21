// Package db provides PostgreSQL access (pgx/v5) and schema migrations.
package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db/sqlc"
	"github.com/jackc/pgx/v5/pgxpool"
	"gorm.io/gorm"
)

// DB wraps a pgxpool.Pool and owns the migration lifecycle.
type DB struct {
	Pool    *pgxpool.Pool
	Queries *sqlc.Queries
	orm     *gorm.DB
	ormSQL  *sql.DB
}

// Open connects to PostgreSQL using dsn, pings, and runs embedded migrations.
func Open(ctx context.Context, dsn string) (*DB, error) {
	d, err := OpenLazy(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := d.Pool.Ping(ctx); err != nil {
		d.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	if err := d.migrate(ctx); err != nil {
		d.Close()
		return nil, fmt.Errorf("db: migrate: %w", err)
	}
	return d, nil
}

// OpenLazy constructs the pool without contacting PostgreSQL or running migrations.
func OpenLazy(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parse DSN: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MinConns = 0
	cfg.ConnConfig.ConnectTimeout = 5 * time.Second
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}
	orm, adapter, err := newORM(pool)
	if err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: initialize ORM: %w", err)
	}
	d := &DB{Pool: pool, Queries: sqlc.New(pool), orm: orm, ormSQL: adapter}
	return d, nil
}

// Close releases all pool connections.
func (d *DB) Close() {
	if d.ormSQL != nil {
		_ = d.ormSQL.Close()
	}
	d.Pool.Close()
}
