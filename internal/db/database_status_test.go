package db

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

type databaseRoleRow struct {
	recovery bool
	err      error
}

func (r databaseRoleRow) Scan(dest ...any) error {
	if r.err == nil {
		*dest[0].(*bool) = r.recovery
	}
	return r.err
}

func TestDatabaseStatusObservedRole(t *testing.T) {
	for _, tc := range []struct {
		name, role string
		row        databaseRoleRow
		reachable  bool
	}{
		{"primary", "primary", databaseRoleRow{}, true},
		{"standby", "standby", databaseRoleRow{recovery: true}, true},
		{"unavailable", "unknown", databaseRoleRow{err: errors.New("private connection error")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := observeDatabaseStatus(DatabaseStatus{ObservedRole: "unknown"}, tc.row)
			if got.ObservedRole != tc.role || got.Reachable != tc.reachable || got.CheckedAt.IsZero() {
				t.Fatalf("unexpected observation: %+v", got)
			}
		})
	}
}

func TestDatabaseStatusUnavailablePreservesSafeConfiguredEndpoint(t *testing.T) {
	d, err := OpenLazy(context.Background(), "postgres://private-user:private-password@127.0.0.1:25432/private-db?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // No connection to PostgreSQL is required by this unit test.
	got := d.DatabaseStatus(ctx)
	if got.ConfiguredHost != "127.0.0.1" || got.ConfiguredPort != 25432 || got.Reachable || got.ObservedRole != "unknown" {
		t.Fatalf("unexpected configured endpoint: %+v", got)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "private-") || strings.Contains(string(raw), "postgres://") {
		t.Fatalf("private DSN details in observation: %s", raw)
	}
}
