package db

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRTCReservationsAndUsage(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	users := NewUserRepo(d)
	repo := NewRTCRepo(d)
	var owners []string
	for range 2 {
		u, e := users.Add(ctx, "vless", "rtc-test")
		if e != nil {
			t.Fatal(e)
		}
		owners = append(owners, u.UUID)
		t.Cleanup(func() { _ = users.Purge(ctx, u.UUID) })
	}
	// Existing unrelated tests may have rows: the isolated database is not production.
	var wg sync.WaitGroup
	var successes atomic.Int32
	for _, owner := range owners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := repo.Put(ctx, RTCAccess{Owner: owner, Generation: uuid.NewString(), RoomHash: []byte(owner), Cipher: []byte("encrypted"), KeyVersion: "test"}, 1, false)
			if e == nil {
				successes.Add(1)
			} else if !errors.Is(e, ErrRTCCapacity) {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("capacity race", successes.Load())
	}
	var owner string
	for _, id := range owners {
		if _, e := repo.Get(ctx, id); e == nil {
			owner = id
		}
	}
	a, e := repo.Get(ctx, owner)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = repo.Put(ctx, a, 1, false); !errors.Is(e, ErrRTCRate) {
		t.Fatal("rate limit", e)
	}
	stale := uuid.NewString()
	if e = repo.Observed(ctx, owner, stale, "ready", "", nil); e != nil {
		t.Fatal(e)
	}
	a, _ = repo.Get(ctx, owner)
	if a.State == "ready" {
		t.Fatal("stale generation accepted")
	}
	hour := time.Now().UTC().Truncate(time.Hour)
	epoch := uuid.NewString()
	usage := RTCUsage{Hour: hour, Up: 1234, Down: 5678}
	for range 3 {
		if e = repo.SaveUsage(ctx, owner, epoch, usage); e != nil {
			t.Fatal(e)
		}
	}
	points, e := repo.Usage(ctx, owner)
	if e != nil || len(points) != 1 || points[0].Up != 1234 || points[0].Down != 5678 {
		t.Fatal("idempotent counters", points, e)
	}
	var count int
	if e = d.Pool.QueryRow(ctx, `SELECT count(*) FROM monthly_traffic WHERE user_uuid=$1`, owner).Scan(&count); e != nil || count != 0 {
		t.Fatal("RTC ingress altered billable traffic", e)
	}
	if e = repo.Disable(ctx, owner); e != nil {
		t.Fatal(e)
	}
	points, e = repo.Usage(ctx, owner)
	if e != nil || len(points) != 1 {
		t.Fatal("history removed", e)
	}
}
