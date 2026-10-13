package db

import (
	"context"
	"fmt"
)

func validatePoolSchema(ctx context.Context, q schemaQuerier) error {
	columns := []accountingColumn{
		{"quota_exit_membership", "exit_id", "text", true}, {"quota_exit_membership", "scope", "text", true},
		{"provider_quota_pools", "scope", "text", true}, {"provider_quota_pools", "period", "text", true},
		{"provider_quota_pools", "accrued_bytes", "bigint", true}, {"provider_quota_pools", "provider_used_bytes", "bigint", true},
		{"provider_quota_pools", "remaining_bytes", "bigint", true}, {"provider_quota_pools", "observed_local_bytes", "bigint", true},
		{"provider_quota_pools", "observed_at", "timestamp with time zone", true}, {"provider_quota_pools", "provider_error", "text", true},
	}
	for _, c := range columns {
		var valid bool
		if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_attribute WHERE attrelid=to_regclass($1) AND attname=$2 AND NOT attisdropped AND format_type(atttypid,atttypmod)=$3 AND attnotnull=$4)`, c.table, c.name, c.kind, c.required).Scan(&valid); err != nil {
			return err
		}
		if !valid {
			return fmt.Errorf("%w: %s.%s", ErrAccountingSchema, c.table, c.name)
		}
	}
	var valid bool
	if err := q.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('quota_exit_membership') AND contype='p' AND pg_get_constraintdef(oid)='PRIMARY KEY (exit_id)') AND
 NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('quota_exit_membership') AND contype='f') AND
 EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid=to_regclass('provider_quota_pools') AND contype='p' AND pg_get_constraintdef(oid)='PRIMARY KEY (scope, period)') AND
 EXISTS(SELECT 1 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid WHERE t.tgrelid=to_regclass('exit_traffic_budgets') AND t.tgname='quota_exit_membership' AND t.tgenabled='O' AND t.tgtype=23 AND NOT t.tgisinternal AND p.proname='remember_quota_exit')`).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return fmt.Errorf("%w: provider pool constraints or membership trigger", ErrAccountingSchema)
	}
	return nil
}
