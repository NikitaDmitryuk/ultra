package db

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// DatabaseStatus describes the application's actual pool, independently of the
// bridge standby. ConfiguredHost may be a local tunnel or proxy, not a DB VM.
// Reachable means the SQL role probe succeeded; false does not diagnose a
// transport failure. ObservedRole stays unknown when that probe fails.
type DatabaseStatus struct {
	// PrimaryHost is deployment metadata, never inferred from the SQL endpoint.
	// nil denotes an older runtime without a physical host projection.
	PrimaryHost    *string   `json:"primary_host"`
	ConfiguredHost string    `json:"configured_host"`
	ConfiguredPort uint16    `json:"configured_port"`
	Reachable      bool      `json:"reachable"`
	ObservedRole   string    `json:"observed_role"`
	CheckedAt      time.Time `json:"checked_at"`
}

// DatabaseStatus never exposes the DSN, credentials, or connection errors.
func (d *DB) DatabaseStatus(ctx context.Context) DatabaseStatus {
	status := DatabaseStatus{ObservedRole: "unknown"}
	if d == nil || d.Pool == nil {
		status.CheckedAt = time.Now().UTC()
		return status
	}
	cfg := d.Pool.Config().ConnConfig
	status.ConfiguredHost, status.ConfiguredPort = cfg.Host, cfg.Port
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return observeDatabaseStatus(status, d.Pool.QueryRow(ctx, `SELECT pg_is_in_recovery()`))
}

func observeDatabaseStatus(status DatabaseStatus, row pgx.Row) DatabaseStatus {
	var recovery bool
	if err := row.Scan(&recovery); err == nil {
		status.Reachable = true
		status.ObservedRole = "primary"
		if recovery {
			status.ObservedRole = "standby"
		}
	}
	status.CheckedAt = time.Now().UTC()
	return status
}
