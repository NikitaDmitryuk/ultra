package db

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/google/uuid"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
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

	only := true
	_, err = repo.Update(ctx, id2, exits.UpdatePatch{Enabled: &only})
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
