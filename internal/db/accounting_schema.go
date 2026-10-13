package db

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"strings"
)

var ErrAccountingSchema = errors.New("incompatible accounting schema")

type schemaQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}
type accountingColumn struct {
	table, name, kind string
	required          bool
}

var accountingColumns = []accountingColumn{
	{"traffic_accounts", "account_id", "uuid", true},
	{"traffic_batches", "node_id", "uuid", true}, {"traffic_batches", "batch_id", "uuid", true}, {"traffic_batches", "digest", "bytea", true}, {"traffic_batches", "committed_at", "timestamp with time zone", true},
	{"account_exit_usage", "account_id", "uuid", true}, {"account_exit_usage", "exit_id", "text", true}, {"account_exit_usage", "period", "text", true}, {"account_exit_usage", "uplink_bytes", "bigint", true}, {"account_exit_usage", "downlink_bytes", "bigint", true}, {"account_exit_usage", "charged_bytes", "bigint", true},
	{"recovery_heartbeat", "singleton", "boolean", true}, {"recovery_heartbeat", "observed_at", "timestamp with time zone", true},
	{"users", "account_id", "uuid", true},
	{"notifications", "attempts", "integer", true}, {"notifications", "next_attempt_at", "timestamp with time zone", true}, {"notifications", "lease_until", "timestamp with time zone", false}, {"notifications", "last_error", "text", true}, {"notifications", "terminal", "boolean", true},
	{"exit_traffic_budgets", "emergency_started_at", "timestamp with time zone", false}, {"exit_traffic_budgets", "emergency_baseline_bytes", "bigint", false}, {"exit_traffic_budgets", "provider_observed_local_bytes", "bigint", true},
	{"vpn_member_notifications", "terminal", "boolean", true}, {"vpn_member_notifications", "last_error", "text", true}, {"vpn_member_notifications", "lease_until", "timestamp with time zone", false},
}

// ValidateAccountingSchema checks the resolved relations, rather than trusting a
// migration number that an older deployment may have used for unrelated DDL.
func (d *DB) ValidateAccountingSchema(ctx context.Context) error {
	return validateAccountingSchema(ctx, d.Pool)
}
func validateAccountingSchema(ctx context.Context, q schemaQuerier) error {
	for _, c := range accountingColumns {
		var valid bool
		err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass($1) AND attname=$2 AND NOT attisdropped AND format_type(atttypid,atttypmod)=$3 AND attnotnull=$4)`, c.table, c.name, c.kind, c.required).Scan(&valid)
		if err != nil {
			return err
		}
		if !valid {
			return fmt.Errorf("%w: %s.%s", ErrAccountingSchema, c.table, c.name)
		}
	}
	defaults := map[string]string{"users.account_id": "gen_random_uuid()", "traffic_accounts.account_id": "gen_random_uuid()", "traffic_batches.committed_at": "now()", "account_exit_usage.uplink_bytes": "0", "account_exit_usage.downlink_bytes": "0", "account_exit_usage.charged_bytes": "0", "notifications.attempts": "0", "notifications.next_attempt_at": "now()", "notifications.last_error": "''::text", "notifications.terminal": "false", "exit_traffic_budgets.provider_observed_local_bytes": "0", "vpn_member_notifications.terminal": "false", "vpn_member_notifications.last_error": "''::text"}
	for key, expected := range defaults {
		parts := strings.SplitN(key, ".", 2)
		var actual string
		if err := q.QueryRow(ctx, `SELECT COALESCE((SELECT pg_get_expr(d.adbin,d.adrelid) FROM pg_attrdef d JOIN pg_attribute a ON a.attrelid=d.adrelid AND a.attnum=d.adnum WHERE d.adrelid=to_regclass($1) AND a.attname=$2),'')`, parts[0], parts[1]).Scan(&actual); err != nil {
			return err
		}
		if actual != expected {
			return fmt.Errorf("%w: default for %s", ErrAccountingSchema, key)
		}
	}
	// These constraints and triggers define durable identity and idempotency.
	var valid bool
	err := q.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('traffic_accounts') AND contype='p' AND pg_get_constraintdef(oid)='PRIMARY KEY (account_id)') AND
 EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('traffic_batches') AND contype='p' AND pg_get_constraintdef(oid)='PRIMARY KEY (node_id, batch_id)') AND
 EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('account_exit_usage') AND contype='p' AND pg_get_constraintdef(oid)='PRIMARY KEY (account_id, exit_id, period)') AND
 EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('users') AND contype='u' AND condeferrable AND condeferred AND pg_get_constraintdef(oid)='UNIQUE (account_id) DEFERRABLE INITIALLY DEFERRED') AND
 EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('users') AND contype='f' AND confrelid=to_regclass('traffic_accounts') AND pg_get_constraintdef(oid) LIKE 'FOREIGN KEY (account_id)%') AND
 EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('account_exit_usage') AND contype='f' AND confrelid=to_regclass('traffic_accounts') AND pg_get_constraintdef(oid) LIKE 'FOREIGN KEY (account_id)%') AND
 NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('account_exit_usage') AND contype='f' AND confrelid<>to_regclass('traffic_accounts')) AND
 EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid=to_regclass('users') AND t.tgname='users_traffic_account' AND t.tgenabled='O' AND t.tgtype=7 AND NOT t.tgisinternal AND p.proname='ensure_traffic_account' AND btrim(p.prosrc, E' \n\r\t')= 'BEGIN INSERT INTO traffic_accounts(account_id) VALUES(NEW.account_id) ON CONFLICT DO NOTHING; RETURN NEW; END') AND
 EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid=to_regclass('users') AND t.tgname='users_immutable_account' AND t.tgenabled='O' AND t.tgtype=19 AND t.tgattr::text=(SELECT attnum::text FROM pg_attribute WHERE attrelid=t.tgrelid AND attname='account_id') AND NOT t.tgisinternal AND p.proname='forbid_account_rotation' AND btrim(p.prosrc, E' \n\r\t')= 'BEGIN IF NEW.account_id IS DISTINCT FROM OLD.account_id THEN RAISE EXCEPTION ''accounting identity is immutable''; END IF; RETURN NEW; END')`).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("%w: accounting constraints or triggers", ErrAccountingSchema)
	}
	return nil
}
func repairAccountingSchema(ctx context.Context, tx pgx.Tx) error {
	if err := validateAccountingSchema(ctx, tx); err == nil {
		return nil
	} else if !errors.Is(err, ErrAccountingSchema) {
		return err
	}
	// Only a completely absent reliability extension can be safely reconstructed.
	// A partial/foreign extension requires an explicit migration, never coercion.
	for _, c := range accountingColumns {
		var present bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass($1) AND attname=$2 AND NOT attisdropped)`, c.table, c.name).Scan(&present); err != nil {
			return err
		}
		if present {
			return fmt.Errorf("%w: partial extension at %s.%s", ErrAccountingSchema, c.table, c.name)
		}
	}
	var present bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass('traffic_accounts') IS NOT NULL OR to_regclass('traffic_batches') IS NOT NULL OR to_regclass('account_exit_usage') IS NOT NULL OR to_regclass('recovery_heartbeat') IS NOT NULL OR to_regclass('notifications_due') IS NOT NULL OR EXISTS(SELECT 1 FROM pg_proc WHERE pronamespace=(SELECT relnamespace FROM pg_class WHERE oid=to_regclass('users')) AND proname IN ('ensure_traffic_account','forbid_account_rotation'))`).Scan(&present); err != nil {
		return err
	}
	if present {
		return fmt.Errorf("%w: partial extension objects", ErrAccountingSchema)
	}
	if _, err := tx.Exec(ctx, migration022); err != nil {
		return fmt.Errorf("repair accounting extension: %w", err)
	}
	return validateAccountingSchema(ctx, tx)
}
