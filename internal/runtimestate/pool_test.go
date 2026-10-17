package runtimestate

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPoolMigrationUsesMaxPerHistoricalOwnerExit(t *testing.T) {
	s, _, now, _ := fixture(t, 1000)
	defer func() { _ = s.Close() }()
	limits := []QuotaLimit{
		{AccountID: "account", ExitID: "a", Period: "2026-10", UsedBytes: 50, LimitBytes: 1000, ExpiresAt: now.Add(time.Hour)},
		{AccountID: "account", ExitID: "b", Period: "2026-10", UsedBytes: 100, LimitBytes: 1000, ExpiresAt: now.Add(time.Hour)},
		{ExitID: "a", Period: "2026-10", UsedBytes: 50, LimitBytes: 1000, ExpiresAt: now.Add(time.Hour)},
		{ExitID: "b", Period: "2026-10", UsedBytes: 100, LimitBytes: 1000, ExpiresAt: now.Add(time.Hour)},
	}
	if err := s.SetQuotaLimits(limits); err != nil {
		t.Fatal(err)
	}
	pool := ProviderPoolID("vultr")
	migrated := []QuotaLimit{
		{
			AccountID:  "account",
			ExitID:     "a",
			PoolScope:  "vultr",
			Period:     "2026-10",
			UsedBytes:  100,
			LimitBytes: 100,
		}, // removed route: deliberately expired
		{AccountID: "account", ExitID: "b", PoolScope: "vultr", Period: "2026-10", LimitBytes: 1000, ExpiresAt: now.Add(time.Hour)},
		{ExitID: "b", PoolScope: "vultr", Period: "2026-10", LimitBytes: 1000, ExpiresAt: now.Add(time.Hour)},
		{
			AccountID:  "account",
			ExitID:     pool,
			Scope:      "provider_pool",
			Period:     "2026-10",
			UsedBytes:  100,
			LimitBytes: 300,
			ExpiresAt:  now.Add(time.Hour),
		},
		{
			ExitID:     pool,
			Scope:      "provider_pool",
			Members:    []string{"a", "b"},
			Period:     "2026-10",
			UsedBytes:  100,
			LimitBytes: 300,
			ExpiresAt:  now.Add(time.Hour),
		},
	}
	if err := s.SetQuotaLimits(migrated); err != nil {
		t.Fatal(err)
	}
	user, global, err := s.PoolUsage("account", "vultr")
	if err != nil || user != 200 || global != 200 {
		t.Fatal("historical spend refunded", user, global, err)
	}
	if left, err := s.Remaining("account", "b"); err != nil || left != 100 {
		t.Fatal(left, err)
	}
	if _, err := s.Remaining("account", "a"); !errors.Is(err, ErrExpired) {
		t.Fatal("deleted route authorized", err)
	}
	if err := s.AppendBatch(TrafficBatch{BatchID: uuid.NewString(), NodeID: s.NodeID(), CollectedAt: *now}); err != nil {
		t.Fatal(err)
	}
	batches, err := s.PendingBatches(0)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range batches {
		for _, sample := range b.Samples {
			if sample.ExitID == pool {
				t.Fatal("virtual pool sent as traffic")
			}
		}
	}
}

func TestFiveClientsAcrossExitsShareOnePool(t *testing.T) {
	s, _, now, _ := fixture(t, ReservationChunk*10)
	defer func() { _ = s.Close() }()
	pool := ProviderPoolID("vultr")
	limits := []QuotaLimit{
		{
			ExitID:     pool,
			Scope:      "provider_pool",
			Members:    []string{"a", "b"},
			Period:     "2026-10",
			LimitBytes: ReservationChunk * 3,
			ExpiresAt:  now.Add(time.Hour),
		},
	}
	for _, exit := range []string{"a", "b"} {
		limits = append(
			limits,
			QuotaLimit{
				ExitID:     exit,
				PoolScope:  "vultr",
				Period:     "2026-10",
				LimitBytes: ReservationChunk * 10,
				ExpiresAt:  now.Add(time.Hour),
			},
		)
	}
	for _, owner := range []string{"1", "2", "3", "4", "5"} {
		limits = append(
			limits,
			QuotaLimit{
				AccountID:  owner,
				ExitID:     pool,
				Scope:      "provider_pool",
				Period:     "2026-10",
				LimitBytes: ReservationChunk * 10,
				ExpiresAt:  now.Add(time.Hour),
			},
		)
		for _, exit := range []string{"a", "b"} {
			limits = append(
				limits,
				QuotaLimit{
					AccountID:  owner,
					ExitID:     exit,
					PoolScope:  "vultr",
					Period:     "2026-10",
					LimitBytes: ReservationChunk * 10,
					ExpiresAt:  now.Add(time.Hour),
				},
			)
		}
	}
	if err := s.SetQuotaLimits(limits); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var total int64
	for _, owner := range []string{"1", "2", "3", "4", "5"} {
		wg.Go(func() {
			for i := range 1024 {
				exit := []string{"a", "b"}[i%2]
				n, err := s.Reserve(owner, exit, 1024)
				if err != nil && !errors.Is(err, ErrQuota) {
					t.Error(err)
				}
				mu.Lock()
				total += n
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if total != ReservationChunk*3 {
		t.Fatal("shared pool multiplied by clients/exits", total)
	}
	for _, exit := range []string{"a", "b"} {
		if n, err := s.Reserve("1", exit, 1); n != 0 || !errors.Is(err, ErrQuota) {
			t.Fatal("exhausted pool allowed traffic", n, err)
		}
	}
}

func TestPoolPersonalLimitCannotResetWithNewExitOrRestart(t *testing.T) {
	s, path, now, _ := fixture(t, ReservationChunk)
	pool := ProviderPoolID("vultr")
	limits := []QuotaLimit{
		{
			ExitID:     pool,
			Scope:      "provider_pool",
			Members:    []string{"exit", "replacement"},
			Period:     "2026-10",
			LimitBytes: ReservationChunk * 10,
			ExpiresAt:  now.Add(time.Hour),
		},
		{
			AccountID:  "account",
			ExitID:     pool,
			Scope:      "provider_pool",
			Period:     "2026-10",
			LimitBytes: ReservationChunk,
			ExpiresAt:  now.Add(time.Hour),
		},
	}
	for _, exit := range []string{"exit", "replacement"} {
		for _, account := range []string{"", "account"} {
			limits = append(
				limits,
				QuotaLimit{
					ExitID:     exit,
					AccountID:  account,
					PoolScope:  "vultr",
					Period:     "2026-10",
					LimitBytes: ReservationChunk * 10,
					ExpiresAt:  now.Add(time.Hour),
				},
			)
		}
	}
	if err := s.SetQuotaLimits(limits); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reserve("account", "exit", 1); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	s.now = func() time.Time { return *now }
	if err = s.SetQuotaLimits(limits); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Reserve("account", "replacement", 1); n != 0 || !errors.Is(err, ErrQuota) {
		t.Fatal("replacement refunded durable reservation", n, err)
	}
}
