package db

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/subscriptionkey"
)

func TestMemberEnrollmentAndReset(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	r := NewMemberRepo(d)
	group, e := r.PutGroup(ctx, VPNGroup{ChatID: -100123, Title: "test", Enabled: true}, 1)
	if e != nil {
		t.Fatal(e)
	}
	token, e := r.Invite(ctx, 123, 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.Enroll(ctx, 124, "wrong", "invite", token, 0); !errors.Is(e, ErrEnrollmentDenied) {
		t.Fatal("wrong target allowed", e)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			source, proof, chat := "group", group.Code, group.ChatID
			if i%2 == 0 {
				source, proof, chat = "invite", token, 0
			}
			_, e := r.Enroll(ctx, 123, "test", source, proof, chat)
			errs <- e
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	m, e := r.Get(ctx, 123)
	if e != nil || !m.Pending {
		t.Fatal("missing pending enrollment", e)
	}
	var count int
	if e = d.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE telegram_id=123`).Scan(&count); e != nil || count != 1 {
		t.Fatal("duplicate enrollment", e)
	}
	snapshot, e := r.Snapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.SetActive(ctx, 123, 1, false); e != nil {
		t.Fatal(e)
	}
	if e = r.Acknowledge(ctx, snapshot); e != nil {
		t.Fatal(e)
	}
	m, e = r.Get(ctx, 123)
	if e != nil || !m.Pending || m.Active {
		t.Fatal("stale acknowledgement", e)
	}
	m, e = r.Enroll(ctx, 123, "test", "group", group.Code, group.ChatID)
	if e != nil || m.Active {
		t.Fatal("reenrollment reenabled disabled user", e)
	}
	if e = r.Reset(ctx, 123, 1, m.UUID); e != nil {
		t.Fatal(e)
	}
	next, e := r.Get(ctx, 123)
	if e != nil || next.UUID == m.UUID || next.TelegramID != 123 || next.Active {
		t.Fatal("reset lost membership", e)
	}
	if e = r.Reset(ctx, 123, 1, m.UUID); e != nil {
		t.Fatal(e)
	}
	again, e := r.Get(ctx, 123)
	if e != nil || again.UUID != next.UUID {
		t.Fatal("reset retry rotated again", e)
	}
}
func TestStableSubscriptionAndLegacyRecovery(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	u, e := NewUserRepo(d).Add(ctx, "vless", "test")
	if e != nil {
		t.Fatal(e)
	}
	keys := &subscriptionkey.Ring{Active: "v1", Keys: map[string]string{"v1": base64.StdEncoding.EncodeToString(make([]byte, 32))}}
	r := NewSubscriptionRepo(d, keys)
	first, e := r.GetOrCreate(ctx, u.UUID)
	if e != nil {
		t.Fatal(e)
	}
	second, e := r.GetOrCreate(ctx, u.UUID)
	if e != nil || second != first {
		t.Fatal("unstable subscription", e)
	}
	noKey := NewSubscriptionRepo(d)
	if _, e = noKey.GetOrCreate(ctx, u.UUID); e == nil {
		t.Fatal("missing key accepted")
	}
	if _, e = noKey.Resolve(ctx, first); e != nil {
		t.Fatal("missing key broke existing subscription", e)
	}
	digest := sha256.Sum256([]byte(first))
	_, e = d.Pool.Exec(ctx, `UPDATE subscription_tokens SET encrypted_token=NULL,key_version=NULL WHERE user_uuid=$1`, u.UUID)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.GetOrCreate(ctx, u.UUID); !errors.Is(e, ErrLegacySubscription) {
		t.Fatal("legacy token rotated", e)
	}
	var hash []byte
	if e = d.Pool.QueryRow(ctx, `SELECT token_hash FROM subscription_tokens WHERE user_uuid=$1`, u.UUID).Scan(&hash); e != nil || string(hash) != string(digest[:]) {
		t.Fatal("legacy hash changed", e)
	}
}

func TestInviteExpiryRevocationAndDisabledIdentity(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	r := NewMemberRepo(d)
	token, e := r.Invite(ctx, 999, 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.Pool.Exec(ctx, `UPDATE vpn_invites SET expires_at=NOW()-INTERVAL '1 second' WHERE recipient=999`); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Enroll(ctx, 999, "expired", "invite", token, 0); !errors.Is(e, ErrEnrollmentDenied) {
		t.Fatal("expired invitation accepted", e)
	}
	token, e = r.Invite(ctx, 998, 1)
	if e != nil {
		t.Fatal(e)
	}
	list, e := r.Invites(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.CancelInvite(ctx, list[0].ID, 1); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Enroll(ctx, 998, "cancelled", "invite", token, 0); !errors.Is(e, ErrEnrollmentDenied) {
		t.Fatal("cancelled invitation accepted", e)
	}
	token, e = r.Invite(ctx, 997, 1)
	if e != nil {
		t.Fatal(e)
	}
	m, e := r.Enroll(ctx, 997, "disabled", "invite", token, 0)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.SetActive(ctx, 997, 1, false); e != nil {
		t.Fatal(e)
	}
	if e = NewUserRepo(d).Purge(ctx, m.UUID); e == nil {
		t.Fatal("disabled Telegram identity could be removed and re-enrolled")
	}
	token, e = r.Invite(ctx, 997, 1)
	if e != nil {
		t.Fatal(e)
	}
	existing, e := r.Enroll(ctx, 997, "again", "invite", token, 0)
	if e != nil || existing.Active || existing.UUID != m.UUID {
		t.Fatal("disabled member reactivated", e)
	}
}

func TestMemberActivitySurvivesSamplePruning(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	r := NewMemberRepo(d)
	token, e := r.Invite(ctx, 789, 1)
	if e != nil {
		t.Fatal(e)
	}
	m, e := r.Enroll(ctx, 789, "activity", "invite", token, 0)
	if e != nil {
		t.Fatal(e)
	}
	if m.LastTrafficAt != nil {
		t.Fatal("unused member marked active")
	}
	traffic := NewTrafficRepo(d)
	if e = traffic.RecordSamples(ctx, []TrafficSample{{UserUUID: m.UUID, CollectedAt: time.Now(), UplinkBytes: 100}}); e != nil {
		t.Fatal(e)
	}
	if _, e = d.Pool.Exec(ctx, `DELETE FROM traffic_stats WHERE user_uuid=$1`, m.UUID); e != nil {
		t.Fatal(e)
	}
	m, e = r.Get(ctx, 789)
	if e != nil || m.LastTrafficAt == nil {
		t.Fatal("lost activity after pruning", e)
	}
	list, e := r.List(ctx)
	if e != nil || len(list) != 1 || list[0].LastTrafficAt == nil {
		t.Fatal("activity missing in list", e)
	}
}

func TestMemberTrafficRoutesAndLegacyTotals(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	r := NewMemberRepo(d)
	token, e := r.Invite(ctx, 456, 1)
	if e != nil {
		t.Fatal(e)
	}
	m, e := r.Enroll(ctx, 456, "traffic", "invite", token, 0)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	traffic := NewTrafficRepo(d)
	if e = traffic.RecordSamples(ctx, []TrafficSample{{UserUUID: m.UUID, CollectedAt: now, UplinkBytes: 10, ExitTag: "direct"}, {UserUUID: m.UUID, CollectedAt: now, DownlinkBytes: 20, ExitTag: "to-exit-test"}, {UserUUID: m.UUID, CollectedAt: now, DownlinkBytes: 5}}); e != nil {
		t.Fatal(e)
	}
	result, e := r.Traffic(ctx, 456, now)
	if e != nil {
		t.Fatal(e)
	}
	if result.Uplink != 10 || result.Downlink != 25 || len(result.Routes) != 3 || len(result.Days) != 1 {
		t.Fatalf("incorrect breakdown: %+v", result)
	}
	all, e := r.Traffic(ctx, 0, now)
	if e != nil || all.Downlink != result.Downlink {
		t.Fatal("overview mismatch", e)
	}
	oldUUID := m.UUID
	if e = r.Reset(ctx, 456, 1, oldUUID); e != nil {
		t.Fatal(e)
	}
	result, e = r.Traffic(ctx, 456, now)
	if e != nil || result.Downlink != 25 || len(result.Routes) != 3 {
		t.Fatal("reset lost route history", e)
	}
}
