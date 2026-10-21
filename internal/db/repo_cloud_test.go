package db

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/google/uuid"
)

func TestCloudConcurrentReservations(t *testing.T) {
	d := openTestDB(t)
	r := NewCloudRepo(d)
	ctx := context.Background()
	offers := make([]cloud.Offer, 8)
	for i := range offers {
		offers[i] = cloud.Offer{ID: uuid.NewString(), Actor: 1, ExpiresAt: time.Now().Add(time.Minute)}
		if err := r.SaveOffer(ctx, offers[i]); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	results := make(chan error, len(offers))
	for _, o := range offers {
		wg.Add(1)
		go func(o cloud.Offer) { defer wg.Done(); _, e := r.Reserve(ctx, o); results <- e }(o)
	}
	wg.Wait()
	close(results)
	count := 0
	for err := range results {
		if err == nil {
			count++
		} else if !errors.Is(err, cloud.ErrLimit) {
			t.Fatal(err)
		}
	}
	if count != cloud.MaxServers {
		t.Fatalf("reserved %d; expected exactly %d", count, cloud.MaxServers)
	}
	ops, err := r.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	op := ops[0]
	op.State = "failed"
	if err = r.Save(ctx, op); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Reserve(ctx, cloud.Offer{ID: uuid.NewString()}); !errors.Is(err, cloud.ErrLimit) {
		t.Fatal("failed VPS freed paid slot", err)
	}
	repeated, err := r.Reserve(ctx, op.Offer)
	if err != nil || repeated.ID != op.ID {
		t.Fatal("non-idempotent reservation", err)
	}
	op.State = "deleted"
	if err = r.Save(ctx, op); err != nil {
		t.Fatal(err)
	}
	for _, o := range offers {
		reserved := false
		for _, existing := range ops {
			reserved = reserved || o.ID == existing.ID
		}
		if !reserved {
			if _, err = r.Reserve(ctx, o); err != nil {
				t.Fatal("deleted slot was not released", err)
			}
			break
		}
	}
}

func TestCloudCapacityLockDoesNotWaitForWorker(t *testing.T) {
	d := openTestDB(t)
	repo := NewCloudRepo(d)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlockWorker, err := repo.Lock(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer unlockWorker()
	unlockCapacity, err := repo.LockCapacity(ctx)
	if err != nil {
		t.Fatal("capacity lock waited behind cloud worker:", err)
	}
	defer unlockCapacity()
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var routeLockAvailable bool
	if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(817365007)`).Scan(&routeLockAvailable); err != nil {
		t.Fatal(err)
	}
	if !routeLockAvailable {
		t.Fatal("capacity lock blocks the shared route/user/traffic advisory lock")
	}
}

func TestRouteCredentialsLifecycle(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	users := NewUserRepo(d)
	routes := NewRouteRepo(d)
	u, err := users.Add(ctx, "vless", "route test")
	if err != nil {
		t.Fatal(err)
	}
	exitID := uuid.NewString()
	_, err = d.Pool.Exec(
		ctx,
		`INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid,enabled) VALUES($1,'test','192.0.2.1',443,$2,false)`,
		exitID,
		uuid.NewString(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err = routes.Publish(ctx, "fra", "Frankfurt", exitID); err != nil {
		t.Fatal(err)
	}
	if published, err := routes.IsPublished(ctx, "fra", exitID); err != nil || !published {
		t.Fatalf("published route not visible: published=%t err=%v", published, err)
	}
	if applied, err := routes.IsApplied(ctx, exitID); err != nil || applied {
		t.Fatalf("new route reported applied: applied=%t err=%v", applied, err)
	}
	loaded, err := users.ListAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var alias, loc string
	for _, v := range loaded {
		if v.UUID == u.UUID {
			if len(v.Routes) != 1 || v.Routes[0].Published {
				t.Fatal("unapplied route exported")
			}
			alias = v.Routes[0].UUID
			loc = v.Routes[0].LocationID
		}
	}
	if alias == "" {
		t.Fatal("missing alias")
	}
	if err = routes.Applied(ctx, exitID); err != nil {
		t.Fatal(err)
	}
	if err = routes.Publish(ctx, "fra", "Frankfurt", exitID); err != nil {
		t.Fatal(err)
	}
	if applied, err := routes.IsApplied(ctx, exitID); err != nil || !applied {
		t.Fatalf("same-target republish reset applied marker: applied=%t err=%v", applied, err)
	}
	var savedAlias, savedLoc string
	if err = d.Pool.QueryRow(ctx, `SELECT uuid::text,location_id::text FROM vpn_route_credentials WHERE user_uuid=$1`, u.UUID).Scan(&savedAlias, &savedLoc); err != nil ||
		savedAlias != alias ||
		savedLoc != loc {
		t.Fatal("publication changed stable credentials", err)
	}
	next, err := users.RotateUUID(ctx, u.UUID)
	if err != nil {
		t.Fatal(err)
	}
	var old int
	if err = d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM vpn_route_credentials WHERE uuid=$1 OR user_uuid=$2`, alias, u.UUID).Scan(&old); err != nil ||
		old != 0 {
		t.Fatal("old credentials survived reset", err)
	}
	if err = d.Pool.QueryRow(ctx, `SELECT uuid::text,location_id::text FROM vpn_route_credentials WHERE user_uuid=$1`, next).Scan(&savedAlias, &savedLoc); err != nil ||
		savedAlias == alias ||
		savedLoc != loc {
		t.Fatal("reset lost location", err)
	}
	replacementID := uuid.NewString()
	if _, err = d.Pool.Exec(ctx,
		`INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid,enabled) VALUES($1,'replacement','192.0.2.2',443,$2,false)`,
		replacementID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if err = routes.Publish(ctx, "fra", "Frankfurt", replacementID); err != nil {
		t.Fatal(err)
	}
	if applied, err := routes.IsApplied(ctx, replacementID); err != nil || applied {
		t.Fatalf("replacement inherited old route applied marker: applied=%t err=%v", applied, err)
	}
}

func TestConcurrentLocationAndUserCreation(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	users := NewUserRepo(d)
	routes := NewRouteRepo(d)
	for i := 0; i < 5; i++ {
		exitID := uuid.NewString()
		if _, e := d.Pool.Exec(ctx, `INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid,enabled) VALUES($1,'test','192.0.2.1',443,$2,false)`, exitID, uuid.NewString()); e != nil {
			t.Fatal(e)
		}
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		wg.Add(2)
		go func() { defer wg.Done(); errs <- routes.Publish(ctx, exitID, "test", exitID) }()
		go func() { defer wg.Done(); _, e := users.Add(ctx, "vless", "concurrent"); errs <- e }()
		wg.Wait()
		close(errs)
		for e := range errs {
			if e != nil {
				t.Fatal(e)
			}
		}
	}
	var missing int
	if e := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users u CROSS JOIN vpn_locations l WHERE u.kind='vless' AND l.published AND NOT EXISTS(SELECT 1 FROM vpn_route_credentials c WHERE c.user_uuid=u.uuid AND c.location_id=l.id)`).Scan(&missing); e != nil ||
		missing != 0 {
		t.Fatal("concurrent publication missed credentials", missing, e)
	}
}

func TestCloudJournalSurvivesRepositoryRestart(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	r := NewCloudRepo(d)
	offer := cloud.Offer{ID: uuid.NewString(), Actor: 1, ExpiresAt: time.Now().Add(time.Minute)}
	if e := r.SaveOffer(ctx, offer); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Reserve(ctx, offer); e != nil {
		t.Fatal(e)
	}
	event := cloud.Event{
		OperationID: offer.ID,
		Phase:       "prepare",
		Outcome:     "failed",
		Code:        "insufficient_funds",
		HTTPStatus:  400,
		DurationMS:  450,
		At:          time.Now(),
	}
	if e := r.RecordEvent(ctx, event); e != nil {
		t.Fatal(e)
	}
	events, e := NewCloudRepo(d).Events(ctx, offer.ID)
	if e != nil || len(events) != 1 || events[0].Code != event.Code || events[0].HTTPStatus != 400 || events[0].Message == "" {
		t.Fatal("journal not recoverable", e)
	}
}

// Replacement identity is a UUID, including for operations persisted before
// canonical JSON writes. Repeated spelling variants must not reserve another VM.
func TestCloudReplacementUUIDCanonicalIdentity(t *testing.T) {
	const sourceID = "aa00bb11-cc22-dd33-ee44-ff5566778899"
	for name, spelling := range map[string]string{
		"uppercase": strings.ToUpper(sourceID),
		"braced":    "{" + strings.ToUpper(sourceID) + "}",
		"compact":   strings.ReplaceAll(strings.ToUpper(sourceID), "-", ""),
		"urn":       "URN:UUID:" + strings.ToUpper(sourceID),
	} {
		t.Run(name, func(t *testing.T) {
			d := openTestDB(t)
			repo := NewCloudRepo(d)
			ctx := context.Background()
			sourceOffer := cloud.Offer{ID: sourceID, Actor: 1, ExpiresAt: time.Now().Add(time.Minute)}
			if err := repo.SaveOffer(ctx, sourceOffer); err != nil {
				t.Fatal(err)
			}
			source, err := repo.Reserve(ctx, sourceOffer)
			if err != nil {
				t.Fatal(err)
			}
			source.State = "ready"
			if err := repo.Save(ctx, source); err != nil {
				t.Fatal(err)
			}
			first := cloud.Offer{ID: uuid.NewString(), Actor: 1, ExpiresAt: time.Now().Add(time.Minute), ReplaceID: spelling}
			if err := repo.SaveOffer(ctx, first); err != nil {
				t.Fatal(err)
			}
			saved, err := repo.Offer(ctx, first.ID)
			if err != nil || saved.ReplaceID != sourceID {
				t.Fatalf("persisted offer identity=%q: %v", saved.ReplaceID, err)
			}
			replacement, err := repo.Reserve(ctx, first)
			if err != nil || replacement.Offer.ReplaceID != sourceID {
				t.Fatalf("reserved identity=%q: %v", replacement.Offer.ReplaceID, err)
			}
			// Save must also canonicalize an operation loaded from historical JSON.
			replacement.Offer.ReplaceID = spelling
			if err := repo.Save(ctx, replacement); err != nil {
				t.Fatal(err)
			}
			current, err := repo.Get(ctx, replacement.ID)
			if err != nil || current.Offer.ReplaceID != sourceID {
				t.Fatalf("saved operation identity=%q: %v", current.Offer.ReplaceID, err)
			}
			// Simulate an existing pre-fix row: no migration or rewrite is required for
			// the reservation guard to recognize the same physical source.
			if _, err := d.Pool.Exec(ctx, `UPDATE cloud_operations SET body=jsonb_set(body,'{offer,replace_id}',to_jsonb($2::text)) WHERE id=$1`, replacement.ID, spelling); err != nil {
				t.Fatal(err)
			}
			repeated, err := repo.Reserve(ctx, first)
			if err != nil || repeated.ID != replacement.ID {
				t.Fatalf("same-offer retry changed reservation: %+v %v", repeated, err)
			}
			second := cloud.Offer{ID: uuid.NewString(), Actor: 1, ExpiresAt: time.Now().Add(time.Minute), ReplaceID: sourceID}
			if err := repo.SaveOffer(ctx, second); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.Reserve(ctx, second); !errors.Is(err, cloud.ErrConflict) {
				t.Fatalf("second replacement of the same UUID accepted: %v", err)
			}
			var count int
			if err := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM cloud_operations`).Scan(&count); err != nil || count != 2 {
				t.Fatalf("operations=%d, want source and one replacement: %v", count, err)
			}
		})
	}
}
