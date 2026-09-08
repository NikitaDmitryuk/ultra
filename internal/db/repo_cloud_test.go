package db

import (
	"context"
	"errors"
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
	if count != 2 {
		t.Fatalf("reserved %d; expected exactly 2", count)
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
		if o.ID != ops[0].ID && o.ID != ops[1].ID {
			if _, err = r.Reserve(ctx, o); err != nil {
				t.Fatal("deleted slot was not released", err)
			}
			break
		}
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
	_, err = d.Pool.Exec(ctx, `INSERT INTO exit_nodes(id,name,address,port,tunnel_uuid,enabled) VALUES($1,'test','192.0.2.1',443,$2,false)`, exitID, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if err = routes.Publish(ctx, "fra", "Frankfurt", exitID); err != nil {
		t.Fatal(err)
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
	var savedAlias, savedLoc string
	if err = d.Pool.QueryRow(ctx, `SELECT uuid::text,location_id::text FROM vpn_route_credentials WHERE user_uuid=$1`, u.UUID).Scan(&savedAlias, &savedLoc); err != nil || savedAlias != alias || savedLoc != loc {
		t.Fatal("publication changed stable credentials", err)
	}
	next, err := users.RotateUUID(ctx, u.UUID)
	if err != nil {
		t.Fatal(err)
	}
	var old int
	if err = d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM vpn_route_credentials WHERE uuid=$1 OR user_uuid=$2`, alias, u.UUID).Scan(&old); err != nil || old != 0 {
		t.Fatal("old credentials survived reset", err)
	}
	if err = d.Pool.QueryRow(ctx, `SELECT uuid::text,location_id::text FROM vpn_route_credentials WHERE user_uuid=$1`, next).Scan(&savedAlias, &savedLoc); err != nil || savedAlias == alias || savedLoc != loc {
		t.Fatal("reset lost location", err)
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
	if e := d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users u CROSS JOIN vpn_locations l WHERE u.kind='vless' AND l.published AND NOT EXISTS(SELECT 1 FROM vpn_route_credentials c WHERE c.user_uuid=u.uuid AND c.location_id=l.id)`).Scan(&missing); e != nil || missing != 0 {
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
	event := cloud.Event{OperationID: offer.ID, Phase: "prepare", Outcome: "failed", Code: "insufficient_funds", HTTPStatus: 400, DurationMS: 450, At: time.Now()}
	if e := r.RecordEvent(ctx, event); e != nil {
		t.Fatal(e)
	}
	events, e := NewCloudRepo(d).Events(ctx, offer.ID)
	if e != nil || len(events) != 1 || events[0].Code != event.Code || events[0].HTTPStatus != 400 || events[0].Message == "" {
		t.Fatal("journal not recoverable", e)
	}
}
