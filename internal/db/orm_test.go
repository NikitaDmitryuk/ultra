package db

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/db/sqlc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOpenLazyORMDoesNotConnect(t *testing.T) {
	d, err := OpenLazy(context.Background(), "postgres://unused:unused@127.0.0.1:1/unused?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if d.orm == nil || d.ormSQL == nil {
		t.Fatal("ORM unavailable")
	}
	if got := d.Pool.Stat().TotalConns(); got != 0 {
		t.Fatalf("lazy startup opened %d connections", got)
	}
}

func TestORMBorrowsExistingPoolAndReleasesConnections(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	cfg := d.Pool.Config()
	cfg.MaxConns = 1
	counter := &statementCounter{}
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	orm, adapter, err := newORM(pool)
	if err != nil {
		pool.Close()
		t.Fatal(err)
	}
	shared := &DB{Pool: pool, Queries: sqlc.New(pool), orm: orm, ormSQL: adapter}
	defer shared.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	c, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	_, err = NewCloudRepo(shared).List(c)
	cancel()
	conn.Release()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ORM escaped exhausted shared pool: %v", err)
	}
	counter.count.Store(0)
	offer := cloud.Offer{ID: uuid.NewString(), Actor: 23, ExpiresAt: time.Now().Add(time.Minute)}
	repo := NewCloudRepo(shared)
	if err := repo.SaveOffer(ctx, offer); err != nil {
		t.Fatal(err)
	}
	if got := counter.count.Load(); got != 1 {
		t.Fatalf("ORM insert used %d statements; want one", got)
	}
	if got := pool.Stat().AcquiredConns(); got != 0 {
		t.Fatalf("ORM retained %d pgx connections", got)
	}
	c, cancel = context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := pool.Ping(c); err != nil {
		t.Fatalf("ORM starved pgx callers: %v", err)
	}
	got, err := repo.Offer(ctx, offer.ID)
	if err != nil || got.ID != offer.ID || got.Actor != offer.Actor {
		t.Fatalf("offer roundtrip %+v: %v", got, err)
	}
	if _, err := repo.Offer(ctx, uuid.NewString()); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("missing-row contract: %v", err)
	}
}

func TestORMCloudPersistsZeroFieldsAndEvents(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	repo := NewCloudRepo(d)
	offer := cloud.Offer{ID: uuid.NewString(), Actor: 42, ExpiresAt: time.Now().Add(time.Minute)}
	if err := repo.SaveOffer(ctx, offer); err != nil {
		t.Fatal(err)
	}
	op, err := repo.Reserve(ctx, offer)
	if err != nil {
		t.Fatal(err)
	}
	op.State = "deleted"
	if err := repo.Save(ctx, op); err != nil {
		t.Fatal(err)
	}
	var occupied bool
	if err := d.Pool.QueryRow(ctx, `SELECT occupies_slot FROM cloud_operations WHERE id=$1`, op.ID).Scan(&occupied); err != nil ||
		occupied {
		t.Fatalf("false update lost: occupied=%v %v", occupied, err)
	}
	got, err := repo.Get(ctx, op.ID)
	if err != nil || got.State != "deleted" {
		t.Fatalf("operation roundtrip %+v: %v", got, err)
	}
	at := time.Date(2026, 10, 15, 1, 2, 3, 0, time.UTC)
	if err := repo.RecordEvent(ctx, cloud.Event{OperationID: op.ID, Phase: "prepare", Outcome: "failed", Code: "unavailable", At: at}); err != nil {
		t.Fatal(err)
	}
	if err := repo.RecordEvent(ctx, cloud.Event{OperationID: op.ID, Phase: "prepare", Outcome: "ready", At: at.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	events, err := repo.Events(ctx, op.ID)
	if err != nil || len(events) != 2 || events[0].Outcome != "ready" || events[1].Code != "unavailable" || !events[1].At.Equal(at) {
		t.Fatalf("events %+v: %v", events, err)
	}
	if err := repo.Audit(ctx, offer.Actor, op.ID, "inspected"); err != nil {
		t.Fatal(err)
	}
	var audit int
	if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM cloud_audit WHERE operation_id=$1`, op.ID).Scan(&audit); err != nil || audit != 2 {
		t.Fatalf("audit=%d: %v", audit, err)
	}
}

// Complex PostgreSQL statements belong in named SQLC sources; ordinary cloud
// CRUD uses typed ORM clauses. Keep this completed conversion from regressing.
func TestConvertedRepositoriesContainNoSQLStatements(t *testing.T) {
	for _, path := range []string{"repo_cloud.go", "repo_traffic_batch.go", "repo_leak.go"} {
		tree, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(tree, func(n ast.Node) bool {
			literal, ok := n.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
			words := strings.Fields(strings.ToUpper(value))
			if len(words) > 1 {
				switch words[0] {
				case "SELECT", "INSERT", "UPDATE", "DELETE", "WITH":
					t.Errorf("%s contains an inline SQL statement", path)
				}
			}
			return true
		})
	}
}
