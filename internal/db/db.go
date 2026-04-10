// Package db provides PostgreSQL access (pgx/v5) and schema migrations.
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps a pgxpool.Pool and owns the migration lifecycle.
type DB struct {
	Pool *pgxpool.Pool
}

// Open connects to PostgreSQL using dsn, pings, and runs embedded migrations.
func Open(ctx context.Context, dsn string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parse DSN: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.HealthCheckPeriod = time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("db: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	d := &DB{Pool: pool}
	if err := d.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: migrate: %w", err)
	}
	return d, nil
}

// Close releases all pool connections.
func (d *DB) Close() {
	d.Pool.Close()
}
