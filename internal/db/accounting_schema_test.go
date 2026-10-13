package db

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"os"
	"testing"
	"time"
)

func removeAccountingExtension(t *testing.T, d *DB) {
	t.Helper()
	_, err := d.Pool.Exec(context.Background(), `
 DROP TABLE account_exit_usage,traffic_batches,traffic_accounts,recovery_heartbeat CASCADE;
 ALTER TABLE users DROP COLUMN account_id CASCADE;
 DROP FUNCTION ensure_traffic_account() CASCADE; DROP FUNCTION forbid_account_rotation() CASCADE;
 DROP INDEX notifications_due;
 ALTER TABLE notifications DROP COLUMN attempts,DROP COLUMN next_attempt_at,DROP COLUMN lease_until,DROP COLUMN last_error,DROP COLUMN terminal;
 ALTER TABLE exit_traffic_budgets DROP COLUMN emergency_started_at,DROP COLUMN emergency_baseline_bytes,DROP COLUMN provider_observed_local_bytes;
 ALTER TABLE vpn_member_notifications DROP COLUMN terminal,DROP COLUMN last_error,DROP COLUMN lease_until;
 DELETE FROM schema_migrations WHERE version=23;`)
	if err != nil {
		t.Fatal(err)
	}
}
func TestAccountingSchemaMigrationCompatibility(t *testing.T) {
	for _, kind := range []string{"fresh21", "foreign22", "ours22", "partial22"} {
		t.Run(kind, func(t *testing.T) {
			d := openTestDB(t)
			ctx := context.Background()
			if _, err := d.Pool.Exec(ctx, `DROP TABLE service_access; DELETE FROM schema_migrations WHERE version=24`); err != nil {
				t.Fatal(err)
			}
			if kind != "ours22" {
				removeAccountingExtension(t, d)
			} else {
				if _, err := d.Pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version=23`); err != nil {
					t.Fatal(err)
				}
			}
			var original22 time.Time
			if err := d.Pool.QueryRow(ctx, `SELECT applied_at FROM schema_migrations WHERE version=22`).Scan(&original22); err != nil {
				t.Fatal(err)
			}
			if kind == "fresh21" {
				if _, err := d.Pool.Exec(ctx, `DELETE FROM schema_migrations WHERE version=22`); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "partial22" {
				if _, err := d.Pool.Exec(ctx, `ALTER TABLE users ADD COLUMN account_id UUID`); err != nil {
					t.Fatal(err)
				}
			}
			if kind != "ours22" {
				if err := d.ValidateAccountingSchema(ctx); !errors.Is(err, ErrAccountingSchema) {
					t.Fatalf("guard accepted incompatible extension: %v", err)
				}
			}
			id := uuid.NewString()
			if _, err := d.Pool.Exec(ctx, `INSERT INTO users(uuid,name) VALUES($1,'migration-fixture')`, id); err != nil {
				t.Fatal(err)
			}
			if _, err := d.Pool.Exec(ctx, `INSERT INTO daily_route_traffic(user_uuid,day,exit_tag,uplink_bytes,downlink_bytes) VALUES($1,CURRENT_DATE,'to-exit-history',123,456)`, id); err != nil {
				t.Fatal(err)
			}
			if kind == "ours22" {
				if _, err := d.Pool.Exec(ctx, `INSERT INTO account_exit_usage(account_id,exit_id,period,charged_bytes) SELECT account_id,'history','2026-10',512 FROM users WHERE uuid=$1`, id); err != nil {
					t.Fatal(err)
				}
			}
			err := d.migrate(ctx)
			if kind == "partial22" {
				if !errors.Is(err, ErrAccountingSchema) {
					t.Fatalf("partial extension not rejected: %v", err)
				}
				var exists bool
				if e := d.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=23)`).Scan(&exists); e != nil || exists {
					t.Fatal("partial migration recorded 23")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = d.ValidateAccountingSchema(ctx); err != nil {
				t.Fatal(err)
			}
			if kind == "ours22" {
				var unchanged bool
				if err := d.Pool.QueryRow(ctx, `SELECT charged_bytes=512 AND uplink_bytes=0 AND downlink_bytes=0 FROM account_exit_usage WHERE exit_id='history'`).Scan(&unchanged); err != nil || !unchanged {
					t.Fatal("compatible22 expense changed")
				}
			}
			if kind != "ours22" {
				var correct bool
				if err = d.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM account_exit_usage WHERE account_id=$1 AND exit_id='history' AND uplink_bytes=123 AND downlink_bytes=456)`, id).Scan(&correct); err != nil || !correct {
					t.Fatal("repair lost historical expense")
				}
			}
			if kind != "fresh21" {
				var recorded time.Time
				if e := d.Pool.QueryRow(ctx, `SELECT applied_at FROM schema_migrations WHERE version=22`).Scan(&recorded); e != nil || !recorded.Equal(original22) {
					t.Fatal("repair rewrote original version22 marker")
				}
			}
			if err = d.migrate(ctx); err != nil {
				t.Fatalf("repeat migration: %v", err)
			}
			var maximum int
			if err = d.Pool.QueryRow(ctx, `SELECT max(version) FROM schema_migrations`).Scan(&maximum); err != nil || maximum != 24 {
				t.Fatalf("migration version %d %v", maximum, err)
			}
		})
	}
}

func TestAccountingSchemaGuardRejectsDriftAfterVersion23(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	if _, err := d.Pool.Exec(ctx, `ALTER TABLE users ALTER COLUMN account_id DROP DEFAULT`); err != nil {
		t.Fatal(err)
	}
	if err := d.migrate(ctx); !errors.Is(err, ErrAccountingSchema) {
		t.Fatalf("version marker masked schema drift: %v", err)
	}
}

// Explicit operator-prepared isolated clone only; never use DATABASE_URL here.
func TestRecoveredAccountingMigrationClone(t *testing.T) {
	dsn := os.Getenv("ULTRA_TEST_RECOVERED_DB_DSN")
	if dsn == "" {
		t.Skip("explicit recovered isolated clone not provided")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := OpenLazy(ctx, dsn)
	if err != nil {
		t.Fatal("isolated recovered clone operation failed")
	}
	defer d.Close()
	var original22 time.Time
	if err = d.Pool.QueryRow(ctx, `SELECT applied_at FROM schema_migrations WHERE version=22`).Scan(&original22); err != nil {
		t.Fatal("clone original marker unavailable")
	}
	var usersBefore, upBefore, downBefore int64
	if err = d.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM users),COALESCE(sum(uplink_bytes),0)::bigint,COALESCE(sum(downlink_bytes),0)::bigint FROM daily_route_traffic`).Scan(&usersBefore, &upBefore, &downBefore); err != nil {
		t.Fatal("isolated recovered clone operation failed")
	}
	if err = d.migrate(ctx); err != nil {
		t.Fatal("isolated recovered clone operation failed")
	}
	if err = d.ValidateAccountingSchema(ctx); err != nil {
		t.Fatal("isolated recovered clone operation failed")
	}
	var recorded time.Time
	if err = d.Pool.QueryRow(ctx, `SELECT applied_at FROM schema_migrations WHERE version=22`).Scan(&recorded); err != nil || !recorded.Equal(original22) {
		t.Fatal("clone repair rewrote original marker")
	}
	var preserved bool
	if err = d.Pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM users)=$1 AND (SELECT COALESCE(sum(uplink_bytes),0)::bigint FROM account_exit_usage)=$2 AND (SELECT COALESCE(sum(downlink_bytes),0)::bigint FROM account_exit_usage)=$3 AND NOT EXISTS(SELECT 1 FROM users WHERE account_id<>uuid)`, usersBefore, upBefore, downBefore).Scan(&preserved); err != nil || !preserved {
		t.Fatal("recovered accounting backfill did not preserve source data")
	}
	if err = d.migrate(ctx); err != nil {
		t.Fatal("isolated recovered clone operation failed")
	}
}
