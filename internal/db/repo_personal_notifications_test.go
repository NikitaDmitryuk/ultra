package db

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/subscriptionkey"
	"github.com/jackc/pgx/v5"
)

func personalFixture(t *testing.T) (*DB, *PersonalNotificationRepo, *UserRepo, *SubscriptionRepo, auth.User) {
	t.Helper()
	d := openTestDB(t)
	ctx := context.Background()
	subscriptions := NewSubscriptionRepo(
		d,
		&subscriptionkey.Ring{Active: "v1", Keys: map[string]string{"v1": base64.StdEncoding.EncodeToString(make([]byte, 32))}},
	)
	users := NewUserRepo(d, subscriptions)
	u, e := users.Add(ctx, "vless", "personal")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = d.Pool.Exec(ctx, `UPDATE users SET telegram_id=12345 WHERE uuid=$1`, u.UUID); e != nil {
		t.Fatal(e)
	}
	u, _, e = users.Lookup(ctx, u.UUID)
	if e != nil {
		t.Fatal(e)
	}
	return d, NewPersonalNotificationRepo(d), users, subscriptions, u
}
func personalOptIn(t *testing.T, r *PersonalNotificationRepo) {
	t.Helper()
	if e := r.PutPreferences(context.Background(), 12345, PersonalNotificationPreferences{true, true, true, true}); e != nil {
		t.Fatal(e)
	}
}
func personalCount(t *testing.T, d *DB) int {
	t.Helper()
	var n int
	if e := d.Pool.QueryRow(context.Background(), `SELECT count(*) FROM personal_notification_events`).Scan(&n); e != nil {
		t.Fatal(e)
	}
	return n
}
func personalConfirm(t *testing.T, r *PersonalNotificationRepo, users *UserRepo) {
	t.Helper()
	ctx := context.Background()
	s, e := r.AccessSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	all, e := users.ListAll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.ConfirmAccess(ctx, s, all); e != nil {
		t.Fatal(e)
	}
}

func TestPersonalPreferencesDefaultsNoReplayAndStableOwner(t *testing.T) {
	d, r, users, subs, u := personalFixture(t)
	ctx := context.Background()
	p, e := r.Preferences(ctx, 12345)
	if e != nil || p != (PersonalNotificationPreferences{}) {
		t.Fatalf("defaults: %+v %v", p, e)
	}
	if _, e = subs.Rotate(ctx, u.UUID); e != nil {
		t.Fatal(e)
	}
	personalOptIn(t, r)
	if personalCount(t, d) != 0 {
		t.Fatal("opt-in replayed history")
	}
	next, e := users.RotateUUID(ctx, u.UUID)
	if e != nil {
		t.Fatal(e)
	}
	p, e = r.Preferences(ctx, 12345)
	if e != nil || !p.Credentials {
		t.Fatal("rotation lost settings")
	}
	n, e := r.Claim(ctx)
	if e != nil || n.Kind != "uuid" {
		t.Fatalf("claim %+v %v", n, e)
	}
	if ok, e := r.Eligible(ctx, &n); !errors.Is(e, ErrPersonalNotificationPending) || ok {
		t.Fatal("UUID change must wait for runtime ack", e)
	}
	personalConfirm(t, r, users)
	if ok, e := r.Eligible(ctx, &n); e != nil || !ok {
		t.Fatal("applied UUID ineligible", e)
	}
	token, e := subs.Existing(ctx, next)
	if e != nil || token == "" {
		t.Fatal("admin UUID reset did not issue current subscription", e)
	}
	if _, e = subs.Rotate(ctx, next); e != nil {
		t.Fatal(e)
	}
	if ok, e := r.Eligible(ctx, &n); e != nil || ok {
		t.Fatal("superseded UUID event eligible", e)
	}
	current, e := subs.Existing(ctx, next)
	if e != nil || token == current {
		t.Fatal("current token not rotated", e)
	}
	if e = users.Remove(ctx, next); e != nil {
		t.Fatal(e)
	}
	if _, e = subs.Existing(ctx, next); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("disabled credential exported", e)
	}
}
func TestPersonalOwnRecoverySuppressionAndExistingNeverMints(t *testing.T) {
	d, r, _, subs, u := personalFixture(t)
	ctx := context.Background()
	personalOptIn(t, r)
	if _, e := subs.Existing(ctx, u.UUID); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal(e)
	}
	var count int
	if e := d.Pool.QueryRow(ctx, `SELECT count(*) FROM subscription_tokens`).Scan(&count); e != nil || count != 0 {
		t.Fatal("read minted token", e)
	}
	if _, e := subs.Rotate(ctx, u.UUID); e != nil {
		t.Fatal(e)
	}
	n, e := r.Claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	// Lost encryption key recovery is an own successful cabinet action.
	replacement := NewSubscriptionRepo(
		d,
		&subscriptionkey.Ring{Active: "v2", Keys: map[string]string{"v2": base64.StdEncoding.EncodeToString(bytesOf(1, 32))}},
	)
	if _, rotated, e := replacement.GetOrReissue(WithPersonalNotificationSuppressed(ctx), u.UUID); e != nil || !rotated {
		t.Fatal("own recovery", e)
	}
	if personalCount(t, d) != 1 {
		t.Fatal("own recovery generated notification")
	}
	if ok, e := r.Eligible(ctx, &n); e != nil || ok {
		t.Fatal("old credential survived own recovery", e)
	}
}
func TestPersonalUUIDIssuanceFailureRollsBack(t *testing.T) {
	d, r, users, _, u := personalFixture(t)
	ctx := context.Background()
	personalOptIn(t, r)
	if _, e := NewUserRepo(d).RotateUUID(ctx, u.UUID); !errors.Is(e, subscriptionkey.ErrUnavailable) {
		t.Fatalf("missing issuer: %v", e)
	}
	if _, ok, e := users.Lookup(ctx, u.UUID); e != nil || !ok {
		t.Fatal("failed UUID operation removed credential", e)
	}
	if personalCount(t, d) != 0 {
		t.Fatal("failed UUID operation enqueued event")
	}
}
func TestPersonalAccessExactAcknowledgementAndNoHistoricalReplay(t *testing.T) {
	d, r, users, _, u := personalFixture(t)
	ctx := context.Background()
	personalOptIn(t, r)
	old, e := r.AccessSnapshot(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if e = users.Remove(ctx, u.UUID); e != nil {
		t.Fatal(e)
	}
	all, e := users.ListAll(ctx)
	if e != nil {
		t.Fatal(e)
	}
	// An earlier apply snapshot must not acknowledge a concurrent disable.
	if e = r.ConfirmAccess(ctx, old, all); e != nil {
		t.Fatal(e)
	}
	if personalCount(t, d) != 1 {
		t.Fatal("desired access mutation was not durably queued")
	}
	n, e := r.Claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if ok, e := r.Eligible(ctx, &n); ok || !errors.Is(e, ErrPersonalNotificationPending) {
		t.Fatal("mismatched/failed apply allowed delivery", e)
	}
	// Failed Apply leaves a durable event awaiting its exact acknowledgement.
	personalConfirm(t, r, users)
	if e != nil || n.Kind != "disabled" {
		t.Fatal("ack did not notify disable", e)
	}
	if ok, e := r.Eligible(ctx, &n); e != nil || !ok {
		t.Fatal("disabled owner must receive access change", e)
	}
	if e = users.Enable(ctx, u.UUID); e != nil {
		t.Fatal(e)
	}
	if ok, e := r.Eligible(ctx, &n); e != nil || ok {
		t.Fatal("superseded disable remains eligible", e)
	}
	personalConfirm(t, r, users)
	if personalCount(t, d) != 2 {
		t.Fatal("missing enable event")
	}
}
func TestPersonalClaimFencingOptOutRestartAndDedupe(t *testing.T) {
	d, r, _, subs, u := personalFixture(t)
	ctx := context.Background()
	personalOptIn(t, r)
	if _, e := subs.Rotate(ctx, u.UUID); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	results := make(chan PersonalNotification, 2)
	for range 2 {
		wg.Go(func() {
			n, e := r.Claim(ctx)
			if e == nil {
				results <- n
			} else if !errors.Is(e, pgx.ErrNoRows) {
				t.Error(e)
			}
		})
	}
	wg.Wait()
	close(results)
	var first PersonalNotification
	count := 0
	for n := range results {
		first = n
		count++
	}
	if count != 1 {
		t.Fatalf("concurrent claims=%d", count)
	}
	if _, e := d.Pool.Exec(ctx, `UPDATE personal_notification_events SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, first.ID); e != nil {
		t.Fatal(e)
	}
	// Reconstructed repository models process restart; lease attempts fence old owner.
	restarted := NewPersonalNotificationRepo(d)
	second, e := restarted.Claim(ctx)
	if e != nil || second.ID != first.ID || second.Attempts != first.Attempts+1 {
		t.Fatal("restart claim", e)
	}
	if e = r.Complete(ctx, first, true, false, 0); e != nil {
		t.Fatal(e)
	}
	var sent *time.Time
	if e = d.Pool.QueryRow(ctx, `SELECT sent_at FROM personal_notification_events WHERE id=$1`, first.ID).Scan(&sent); e != nil ||
		sent != nil {
		t.Fatal("stale claim acknowledged", e)
	}
	if ok, e := r.Eligible(ctx, &first); e != nil || ok {
		t.Fatal("stale claim eligible", e)
	}
	if e = r.PutPreferences(ctx, 12345, PersonalNotificationPreferences{}); e != nil {
		t.Fatal(e)
	}
	personalOptIn(t, r)
	if ok, e := r.Eligible(ctx, &second); e != nil || ok {
		t.Fatal("opt-out/re-optin replayed event", e)
	}
	if e = r.Complete(ctx, second, false, true, 0); e != nil {
		t.Fatal(e)
	}
	if _, e = r.Claim(ctx); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("terminal event reclaimed", e)
	}
	tx, e := d.Pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for range 2 {
		if e = enqueuePersonal(ctx, tx, second.Account, "credentials", "subscription_token", second.Revision, 0); e != nil {
			t.Fatal(e)
		}
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	if personalCount(t, d) != 1 {
		t.Fatal("insert-level dedupe failed")
	}
}

func TestPersonalAvailabilityDurationsCooldownUnknownAndQuota(t *testing.T) {
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	st := personalObservation{}
	down := PersonalRouteObservation{Known: true}
	up := PersonalRouteObservation{Known: true, Available: true}
	for i := 0; i < 5; i++ {
		_, a := st.observe(down, now.Add(time.Duration(i)*time.Minute))
		if a != "" {
			t.Fatal("onset before five minutes")
		}
	}
	_, a := st.observe(down, now.Add(5*time.Minute))
	if a != "down" {
		t.Fatal("missing onset")
	}
	// Save/reload is the persistent state representation.
	raw, e := json.Marshal(st)
	if e != nil {
		t.Fatal(e)
	}
	var restarted personalObservation
	if e = json.Unmarshal(raw, &restarted); e != nil {
		t.Fatal(e)
	}
	st = restarted
	for i := 6; i < 8; i++ {
		_, a = st.observe(up, now.Add(time.Duration(i)*time.Minute))
		if a != "" {
			t.Fatal("early recovery")
		}
	}
	_, a = st.observe(up, now.Add(8*time.Minute))
	if a != "recovered" {
		t.Fatal("missing recovery")
	}
	for i := 9; i < 38; i++ {
		_, a = st.observe(down, now.Add(time.Duration(i)*time.Minute))
		if a != "" {
			t.Fatal("cooldown bypass")
		}
	}
	_, a = st.observe(down, now.Add(38*time.Minute))
	if a != "down" {
		t.Fatal("continuing incident not released after cooldown")
	}
	st = personalObservation{}
	for i := 0; i < 5; i++ {
		st.observe(down, now.Add(time.Duration(i)*time.Minute))
	}
	st.observe(PersonalRouteObservation{}, now.Add(5*time.Minute))
	_, a = st.observe(down, now.Add(6*time.Minute))
	if a != "" {
		t.Fatal("unknown did not reset confirmation")
	}
	st = personalObservation{}
	q := PersonalRouteObservation{Known: true, QuotaBlocked: true}
	for i := 0; i < 10; i++ {
		_, a = st.observe(q, now.Add(time.Duration(i)*time.Minute))
		if a != "" {
			t.Fatal("quota duplicated as outage")
		}
	}
	quota, a := st.observe(up, now.Add(10*time.Minute))
	if quota != "restored" || a != "" {
		t.Fatal("quota restoration promised outage recovery")
	}
}

func TestPersonalRecoveryRequiresDeliveredOnset(t *testing.T) {
	d, r, _, _, u := personalFixture(t)
	ctx := context.Background()
	personalOptIn(t, r)
	now := time.Now().UTC()
	v := PersonalRouteObservation{Account: u.AccountID, Known: true}
	for i := 0; i <= 5; i++ {
		if e := r.Observe(ctx, []PersonalRouteObservation{v}, now.Add(time.Duration(i)*time.Minute)); e != nil {
			t.Fatal(e)
		}
	}
	onset, e := r.Claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if ok, e := r.Eligible(ctx, &onset); e != nil || !ok {
		t.Fatal("onset not eligible", e)
	}
	v.Available = true
	for i := 6; i <= 8; i++ {
		if e = r.Observe(ctx, []PersonalRouteObservation{v}, now.Add(time.Duration(i)*time.Minute)); e != nil {
			t.Fatal(e)
		}
	}
	recovery, e := r.Claim(ctx)
	if e != nil || recovery.Kind != "recovered" {
		t.Fatal("missing recovery", e)
	}
	if ok, e := r.Eligible(ctx, &recovery); e != nil || ok {
		t.Fatal("recovery without delivered onset", e)
	}
	if e = r.Complete(ctx, onset, true, false, 0); e != nil {
		t.Fatal(e)
	}
	if ok, e := r.Eligible(ctx, &recovery); e != nil || !ok {
		t.Fatal("delivered onset recovery eligibility", e)
	}
	// A temporary failure must retain the recovery for retry until an opposite
	// condition is confirmed, without promising that VPN is currently working.
	v.Available = false
	if e = r.Observe(ctx, []PersonalRouteObservation{v}, now.Add(9*time.Minute)); e != nil {
		t.Fatal(e)
	}
	if ok, e := r.Eligible(ctx, &recovery); ok || !errors.Is(e, ErrPersonalNotificationPending) {
		t.Fatal("temporary failure must wait, not promise VPN or become terminal", e)
	}
	for i := 10; i <= 14; i++ {
		if e = r.Observe(ctx, []PersonalRouteObservation{v}, now.Add(time.Duration(i)*time.Minute)); e != nil {
			t.Fatal(e)
		}
	}
	if ok, e := r.Eligible(ctx, &recovery); ok || e != nil {
		t.Fatal("confirmed opposite must terminally supersede recovery", e)
	}
	// Deleted owners cannot receive queued state or secrets.
	if _, e = d.Pool.Exec(ctx, `DELETE FROM users WHERE uuid=$1`, u.UUID); e != nil {
		t.Fatal(e)
	}
	if ok, e := r.Eligible(ctx, &recovery); e != nil || ok {
		t.Fatal("deleted owner eligible", e)
	}
}
func TestPersonalRetryBudget(t *testing.T) {
	d, r, _, subs, u := personalFixture(t)
	ctx := context.Background()
	personalOptIn(t, r)
	if _, e := subs.Rotate(ctx, u.UUID); e != nil {
		t.Fatal(e)
	}
	for range PersonalNotificationMaxAttempts {
		n, e := r.Claim(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if e = r.Complete(ctx, n, false, false, 0); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := r.Claim(ctx); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("retry budget not terminal", e)
	}
	if personalCount(t, d) != 1 {
		t.Fatal("retry duplicated event")
	}
}

func TestPersonalRotationPreservesOptOutAndServiceWithoutKey(t *testing.T) {
	for _, service := range []bool{false, true} {
		t.Run(map[bool]string{false: "optout", true: "service"}[service], func(t *testing.T) {
			d, r, _, _, u := personalFixture(t)
			ctx := context.Background()
			if service {
				personalOptIn(t, r)
				if _, e := d.Pool.Exec(ctx, `INSERT INTO service_access(name,account_id,targets) VALUES('monitor',$1,ARRAY['example.com'])`, u.AccountID); e != nil {
					t.Fatal(e)
				}
			}
			// Production constructs the issuer even when the key ring is unavailable.
			users := NewUserRepo(d, NewSubscriptionRepo(d))
			next, e := users.RotateUUID(ctx, u.UUID)
			if e != nil {
				t.Fatal("legacy rotation blocked by absent ring", e)
			}
			var count int
			if e = d.Pool.QueryRow(ctx, `SELECT count(*) FROM subscription_tokens WHERE user_uuid=$1`, next).Scan(&count); e != nil ||
				count != 0 {
				t.Fatal("service/optout without key issued token", e)
			}
		})
	}
}
func TestPersonalOwnResetAndRetryIsIdempotent(t *testing.T) {
	d, r, _, subs, u := personalFixture(t)
	ctx := context.Background()
	personalOptIn(t, r)
	if _, e := d.Pool.Exec(ctx, `UPDATE users SET enrollment_source='invite' WHERE uuid=$1`, u.UUID); e != nil {
		t.Fatal(e)
	}
	members := NewMemberRepo(d)
	members.Subscriptions = subs
	if e := members.Reset(ctx, 12345, 12345, u.UUID); e != nil {
		t.Fatal(e)
	}
	first, e := members.Get(ctx, 12345)
	if e != nil {
		t.Fatal(e)
	}
	if e = members.Reset(ctx, 12345, 12345, u.UUID); e != nil {
		t.Fatal(e)
	}
	second, e := members.Get(ctx, 12345)
	if e != nil || first.UUID != second.UUID {
		t.Fatal("uncertain reset retry rotated again", e)
	}
	if personalCount(t, d) != 0 {
		t.Fatal("own reset duplicated cabinet success")
	}
}

func TestPersonalAvailabilityReconfirmsAfterGapAndPersistsCooldown(t *testing.T) {
	d, r, _, _, u := personalFixture(t)
	ctx := context.Background()
	personalOptIn(t, r)
	now := time.Now().UTC()
	observe := func(at time.Duration, available bool) {
		t.Helper()
		if e := r.Observe(ctx, []PersonalRouteObservation{{Account: u.AccountID, Known: true, Available: available}}, now.Add(at)); e != nil {
			t.Fatal(e)
		}
	}
	pending := func(n *PersonalNotification) {
		t.Helper()
		if ok, e := r.Eligible(ctx, n); ok || !errors.Is(e, ErrPersonalNotificationPending) {
			t.Fatalf("unconfirmed notification eligible=%v err=%v", ok, e)
		}
	}
	ready := func(n *PersonalNotification) {
		t.Helper()
		if ok, e := r.Eligible(ctx, n); !ok || e != nil {
			t.Fatalf("confirmed notification eligible=%v err=%v", ok, e)
		}
	}
	for i := 0; i <= 5; i++ {
		observe(time.Duration(i)*time.Minute, false)
	}
	onset, e := r.Claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	ready(&onset)
	// A restarted observer cannot treat the unmeasured gap as continuous down.
	r = NewPersonalNotificationRepo(d)
	observe(8*time.Minute, false)
	pending(&onset)
	for i := 9; i < 13; i++ {
		observe(time.Duration(i)*time.Minute, false)
		pending(&onset)
	}
	observe(13*time.Minute, false)
	ready(&onset)
	if e = r.Complete(ctx, onset, true, false, 0); e != nil {
		t.Fatal(e)
	}
	for i := 14; i <= 16; i++ {
		observe(time.Duration(i)*time.Minute, true)
	}
	recovery, e := r.Claim(ctx)
	if e != nil || recovery.Kind != "recovered" {
		t.Fatal("recovery missing", e)
	}
	ready(&recovery)
	r = NewPersonalNotificationRepo(d)
	observe(19*time.Minute, true)
	pending(&recovery)
	observe(20*time.Minute, true)
	pending(&recovery)
	observe(21*time.Minute, true)
	ready(&recovery)
	if e = r.Complete(ctx, recovery, true, false, 0); e != nil {
		t.Fatal(e)
	}
	// RecoveredAt=16m survives a repository restart. No new incident before46m.
	for i := 22; i < 46; i++ {
		observe(time.Duration(i)*time.Minute, false)
	}
	if personalCount(t, d) != 2 {
		t.Fatal("restart lost cooldown")
	}
	r = NewPersonalNotificationRepo(d)
	observe(46*time.Minute, false)
	next, e := r.Claim(ctx)
	if e != nil || next.Kind != "down" || next.Incident != onset.Incident+1 {
		t.Fatal("continued outage did not leave persisted cooldown", e)
	}
	ready(&next)
}

func TestPersonalPendingOnsetSurvivesTransientHealthySample(t *testing.T) {
	d, r, _, _, u := personalFixture(t)
	ctx := context.Background()
	personalOptIn(t, r)
	now := time.Now().UTC()
	observe := func(at time.Duration, available bool) {
		t.Helper()
		if e := r.Observe(ctx, []PersonalRouteObservation{{Account: u.AccountID, Known: true, Available: available}}, now.Add(at)); e != nil {
			t.Fatal(e)
		}
	}
	for i := 0; i <= 5; i++ {
		observe(time.Duration(i)*time.Minute, false)
	}
	n, e := r.Claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if ok, e := r.Eligible(ctx, &n); e != nil || !ok {
		t.Fatal("onset initially ineligible", e)
	}
	// A Telegram transport error retains the event for retry.
	if e = r.Complete(ctx, n, false, false, 0); e != nil {
		t.Fatal(e)
	}
	observe(6*time.Minute, true)
	n, e = r.Claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if ok, e := r.Eligible(ctx, &n); ok || !errors.Is(e, ErrPersonalNotificationPending) {
		t.Fatal("temporary health must be retriable", e)
	}
	// This is the same classification the prepare503 sender persists.
	if e = r.Complete(ctx, n, false, false, 0); e != nil {
		t.Fatal(e)
	}
	r = NewPersonalNotificationRepo(d)
	observe(6*time.Minute+10*time.Second, false)
	for i := 7; i <= 11; i++ {
		observe(time.Duration(i)*time.Minute+10*time.Second, false)
	}
	n, e = r.Claim(ctx)
	if e != nil {
		t.Fatal("retained onset lost", e)
	}
	if ok, e := r.Eligible(ctx, &n); e != nil || !ok {
		t.Fatal("continued down never made retained onset ready", e)
	}
	if personalCount(t, d) != 1 {
		t.Fatal("transient health created a second incident")
	}
	// Confirmed two-minute recovery permanently supersedes the same onset.
	for i := 12; i <= 14; i++ {
		observe(time.Duration(i)*time.Minute, true)
	}
	if ok, e := r.Eligible(ctx, &n); e != nil || ok {
		t.Fatal("confirmed opposite must supersede onset", e)
	}
}

func TestPersonalTokenChangeCannotBypassUUIDAcknowledgement(t *testing.T) {
	_, r, users, subs, u := personalFixture(t)
	ctx := context.Background()
	personalOptIn(t, r)
	personalConfirm(t, r, users)
	next, e := users.RotateUUID(ctx, u.UUID)
	if e != nil {
		t.Fatal(e)
	}
	uuidEvent, e := r.Claim(ctx)
	if e != nil {
		t.Fatal(e)
	}
	token, e := subs.Rotate(ctx, next)
	if e != nil {
		t.Fatal(e)
	}
	tokenEvent, e := r.Claim(ctx)
	if e != nil || tokenEvent.Kind != "subscription_token" {
		t.Fatal("missing token event", e)
	}
	if ok, e := r.Eligible(ctx, &uuidEvent); e != nil || ok {
		t.Fatal("superseded UUID event survived", e)
	}
	if ok, e := r.Eligible(ctx, &tokenEvent); ok || !errors.Is(e, ErrPersonalNotificationPending) {
		t.Fatal("token event bypassed UUID runtime acknowledgement", e)
	}
	personalConfirm(t, r, users)
	if ok, e := r.Eligible(ctx, &tokenEvent); e != nil || !ok {
		t.Fatal("applied token event never became ready", e)
	}
	if current, e := subs.Existing(ctx, next); e != nil || current != token {
		t.Fatal("sender did not read existing current token", e)
	}
}

func TestPersonalAccessConsentCapturedAtMutationBeforeLateAck(t *testing.T) {
	d, r, users, _, u := personalFixture(t)
	ctx := context.Background()
	// Subscription was off when disable was requested. Late apply success must
	// not turn enabling the preference into replay of that earlier mutation.
	if e := users.Remove(ctx, u.UUID); e != nil {
		t.Fatal(e)
	}
	personalOptIn(t, r)
	personalConfirm(t, r, users)
	if personalCount(t, d) != 0 {
		t.Fatal("late access ack replayed pre-optin mutation")
	}
	if _, e := r.Claim(ctx); !errors.Is(e, pgx.ErrNoRows) {
		t.Fatal("historical access event was claimable", e)
	}
	// A new desired change while opted in is durable but awaits exact apply.
	if e := users.Enable(ctx, u.UUID); e != nil {
		t.Fatal(e)
	}
	n, e := r.Claim(ctx)
	if e != nil || n.Kind != "enabled" {
		t.Fatal("opted-in mutation not queued", e)
	}
	if ok, e := r.Eligible(ctx, &n); ok || !errors.Is(e, ErrPersonalNotificationPending) {
		t.Fatal("unapplied desired change eligible", e)
	}
	personalConfirm(t, r, users)
	if ok, e := r.Eligible(ctx, &n); e != nil || !ok {
		t.Fatal("confirmed access event never ready", e)
	}
	// The acknowledgement must never recreate an event invalidated by optout.
	if e = r.PutPreferences(ctx, 12345, PersonalNotificationPreferences{}); e != nil {
		t.Fatal(e)
	}
	personalOptIn(t, r)
	personalConfirm(t, r, users)
	if personalCount(t, d) != 1 {
		t.Fatal("ack recreated historical event")
	}
	if ok, e := r.Eligible(ctx, &n); e != nil || ok {
		t.Fatal("re-optin revived old access event", e)
	}
}
