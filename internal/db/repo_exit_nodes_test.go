package db

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	control, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect test db: %v", err)
	}
	schema := pgx.Identifier{"ultra_test_" + uuid.NewString()}.Sanitize()
	if _, err = control.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		_ = control.Close(ctx)
		t.Fatalf("create test schema: %v", err)
	}
	t.Cleanup(func() {
		if _, err := control.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop test schema: %v", err)
		}
		if err := control.Close(ctx); err != nil {
			t.Errorf("close test schema connection: %v", err)
		}
	})
	// Each test owns its migrations and fixtures; never fall back to public.
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatalf("parse test db URL: %v", err)
		}
		query := u.Query()
		query.Set("search_path", schema)
		u.RawQuery = query.Encode()
		dsn = u.String()
	} else {
		dsn += " search_path='" + schema + "'"
	}
	database, err := Open(ctx, dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(database.Close)
	return database
}

func TestExitNodeRepoUpdateEnabled(t *testing.T) {
	database := openTestDB(t)
	ctx := context.Background()
	repo := NewExitNodeRepo(database)

	id1 := uuid.NewString()
	id2 := uuid.NewString()
	uuid1 := uuid.NewString()
	uuid2 := uuid.NewString()
	t.Cleanup(func() {
		_, _ = database.Pool.Exec(context.Background(), `DELETE FROM exit_nodes WHERE id IN ($1,$2)`, id1, id2)
	})

	for _, row := range []struct {
		id, name, addr, tun string
		priority            int
	}{
		{id1, "primary-test", "203.0.113.10", uuid1, 100},
		{id2, "backup-test", "203.0.113.11", uuid2, 200},
	} {
		_, err := database.Pool.Exec(ctx, `
			INSERT INTO exit_nodes(id, name, address, port, tunnel_uuid, priority, enabled)
			VALUES($1,$2,$3,51001,$4,$5,TRUE)`,
			row.id, row.name, row.addr, row.tun, row.priority,
		)
		if err != nil {
			t.Fatalf("insert %s: %v", row.name, err)
		}
	}

	disabled := false
	updated, err := repo.Update(ctx, id1, exits.UpdatePatch{Enabled: &disabled})
	if err != nil {
		t.Fatalf("Update enabled=false: %v", err)
	}
	if updated.Enabled {
		t.Fatal("expected primary disabled")
	}
	if updated.Priority != 100 || updated.Name != "primary-test" {
		t.Fatalf("unexpected row mutation: %+v", updated)
	}

	newName := "backup-renamed"
	updated, err = repo.Update(ctx, id2, exits.UpdatePatch{Name: &newName})
	if err != nil {
		t.Fatalf("Update name: %v", err)
	}
	if updated.Name != newName {
		t.Fatalf("name=%q", updated.Name)
	}

	// Enabling an already enabled node is valid; disabling the last one is not.
	only := true
	if _, err = repo.Update(ctx, id2, exits.UpdatePatch{Enabled: &only}); err != nil {
		t.Fatal(err)
	}
	_, err = repo.Update(ctx, id2, exits.UpdatePatch{Enabled: &disabled})
	if !errors.Is(err, ErrExitLastEnabled) {
		t.Fatalf("expected ErrExitLastEnabled, got %v", err)
	}
}

func TestExitNodeRepoMergeBootstrapEnabled(t *testing.T) {
	database := openTestDB(t)
	ctx := context.Background()
	repo := NewExitNodeRepo(database)

	id := uuid.NewString()
	tun := uuid.NewString()
	t.Cleanup(func() {
		_, _ = database.Pool.Exec(context.Background(), `DELETE FROM exit_nodes WHERE id=$1`, id)
	})

	_, err := database.Pool.Exec(ctx, `
		INSERT INTO exit_nodes(id, name, address, port, tunnel_uuid, priority, enabled)
		VALUES($1,'merge-test','203.0.113.20',51001,$2,100,TRUE)`,
		id, tun,
	)
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	if err := repo.mergeBootstrapEntry(ctx, exits.BootstrapEntry{
		Name:       "merge-test",
		Address:    "203.0.113.20",
		Port:       51001,
		TunnelUUID: tun,
		Priority:   150,
		Enabled:    exits.BootstrapEnabledPtr(false),
	}); err != nil {
		t.Fatalf("mergeBootstrapEntry: %v", err)
	}

	n, err := repo.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if n.Enabled {
		t.Fatal("expected enabled=false from bootstrap merge")
	}
	if n.Priority != 150 {
		t.Fatalf("priority=%d", n.Priority)
	}
}

func TestBootstrapDoesNotResurrectDisabledOrDeletedExit(t *testing.T) {
	database := openTestDB(t)
	ctx := context.Background()
	repo := NewExitNodeRepo(database)
	nl, err := repo.Add(ctx, exits.AddParams{Name: "nl", Address: "203.0.113.10", Port: 51001})
	if err != nil {
		t.Fatal(err)
	}
	us, err := repo.Add(ctx, exits.AddParams{Name: "us", Address: "203.0.113.11", Port: 51001})
	if err != nil {
		t.Fatal(err)
	}
	disabled := false
	if _, err = repo.Update(ctx, us.ID, exits.UpdatePatch{Enabled: &disabled}); err != nil {
		t.Fatal(err)
	}
	spec := &config.Spec{}
	spec.Exit.Address = us.Address
	spec.Exit.Port = us.Port
	spec.Exit.TunnelUUID = us.TunnelUUID
	if err = repo.Bootstrap(ctx, spec, ""); err != nil {
		t.Fatal(err)
	}
	got, err := repo.Get(ctx, us.ID)
	if err != nil || got.Enabled {
		t.Fatalf("bootstrap reenabled disabled exit %v %v", got, err)
	}
	if err = repo.Delete(ctx, us.ID); err != nil {
		t.Fatal(err)
	}
	if err = repo.Bootstrap(ctx, spec, ""); err != nil {
		t.Fatal(err)
	}
	nodes, err := repo.List(ctx)
	if err != nil || len(nodes) != 1 || nodes[0].ID != nl.ID {
		t.Fatalf("bootstrap resurrected deleted exit %v %v", nodes, err)
	}
}

func TestDeleteExitPreservesLateAccountingAndReplacementIdentity(t *testing.T) {
	database := openTestDB(t)
	ctx := context.Background()
	repo := NewExitNodeRepo(database)
	_, err := repo.Add(ctx, exits.AddParams{Name: "nl", Address: "203.0.113.10", Port: 51001})
	if err != nil {
		t.Fatal(err)
	}
	us, err := repo.Add(ctx, exits.AddParams{Name: "us", Address: "203.0.113.11", Port: 51001})
	if err != nil {
		t.Fatal(err)
	}
	owner := uuid.NewString()
	at := time.Now().UTC()
	period := at.Format("2006-01")
	batch := runtimestate.TrafficBatch{
		Version:     1,
		NodeID:      uuid.NewString(),
		BatchID:     uuid.NewString(),
		CollectedAt: at,
		Samples: []runtimestate.Sample{
			{AccountID: owner, ExitID: us.ID, ExitTag: "to-exit-" + us.ID, Period: period, UplinkBytes: 10, ChargeTotalBytes: 262144},
		},
	}
	traffic := NewTrafficRepo(database)
	if err = traffic.RecordBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if err = repo.Delete(ctx, us.ID); err != nil {
		t.Fatal(err)
	}
	batch.BatchID = uuid.NewString()
	batch.Samples[0].ChargeTotalBytes = 524288
	if err = traffic.RecordBatch(ctx, batch); err != nil {
		t.Fatal(err)
	}
	replacement, err := repo.Add(ctx, exits.AddParams{Name: "us-replacement", Address: us.Address, Port: us.Port})
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ID == us.ID || replacement.TunnelUUID == us.TunnelUUID {
		t.Fatal("replacement reused deleted identity")
	}
	var charge, up int64
	if err = database.Pool.QueryRow(ctx, `SELECT charged_bytes,uplink_bytes FROM account_exit_usage WHERE account_id=$1 AND exit_id=$2 AND period=$3`, owner, us.ID, period).Scan(&charge, &up); err != nil ||
		charge != 524288 ||
		up != 20 {
		t.Fatalf("deleted cost lost %d %d %v", charge, up, err)
	}
	var count int
	if err = database.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM account_exit_usage WHERE exit_id=$1`, replacement.ID).Scan(&count); err != nil ||
		count != 0 {
		t.Fatalf("replacement stole historical accounting %d %v", count, err)
	}
}

func TestConcurrentDeletesPreserveLastEnabledExit(t *testing.T) {
	database := openTestDB(t)
	ctx := context.Background()
	repo := NewExitNodeRepo(database)
	first, err := repo.Add(ctx, exits.AddParams{Name: "one", Address: "203.0.113.10", Port: 51001})
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.Add(ctx, exits.AddParams{Name: "two", Address: "203.0.113.11", Port: 51001})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, id := range []string{first.ID, second.ID} {
		go func() { <-start; results <- repo.Delete(ctx, id) }()
	}
	close(start)
	var successes, protected int
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else if errors.Is(err, ErrExitLastEnabled) {
			protected++
		} else {
			t.Fatal(err)
		}
	}
	count, err := repo.CountEnabled(ctx)
	if err != nil || successes != 1 || protected != 1 || count != 1 {
		t.Fatalf("last enabled guard raced %d %d %d %v", successes, protected, count, err)
	}
}

func TestBootstrapImportFailureRollsBackAllEntries(t *testing.T) {
	database := openTestDB(t)
	ctx := context.Background()
	repo := NewExitNodeRepo(database)
	path := filepath.Join(t.TempDir(), "bootstrap.json")
	if err := os.WriteFile(path, []byte(`[{"name":"first","address":"203.0.113.10","port":51001},{"name":"bad","address":"","port":0}]`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := repo.Bootstrap(ctx, nil, path); err == nil {
		t.Fatal("invalid import accepted")
	}
	nodes, err := repo.List(ctx)
	if err != nil || len(nodes) != 0 {
		t.Fatalf("partial bootstrap committed %v %v", nodes, err)
	}
}
