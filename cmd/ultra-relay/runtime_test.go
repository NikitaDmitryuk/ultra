package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
)

func TestRecoveryReceiptFreshness(t *testing.T) {
	now := time.Unix(1800000000, 0)
	path := filepath.Join(t.TempDir(), "receipt.json")
	if recoveryStatus(path, now)["ready"] != false {
		t.Fatal("missing receipt reported ready")
	}
	for _, tc := range []struct {
		name               string
		age, completion    int64
		independent, ready bool
	}{
		{"same provider fresh", 120, -10, false, true},
		{"independent fresh", 300, -10, true, true},
		{"stale", 301, -10, true, false},
		{"future snapshot", -1, 0, true, false},
		{"future completion", 100, 61, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := json.Marshal(
				map[string]any{
					"snapshot_at":  now.Unix() - tc.age,
					"completed_at": now.Unix() + tc.completion,
					"independent":  tc.independent,
				},
			)
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			got := recoveryStatus(path, now)
			if got["ready"] != tc.ready {
				t.Fatalf("receipt readiness: %v", got)
			}
			if tc.ready && got["independent"] != tc.independent {
				t.Fatal("provider independence lost")
			}
		})
	}
	for _, data := range []string{"{", string(make([]byte, 4097))} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if recoveryStatus(path, now)["ready"] != false {
			t.Fatal("corrupt receipt reported ready")
		}
	}
}

type testRuntimeRunner struct {
	configs  [][]byte
	users    []auth.User
	closed   bool
	failNext bool
}

func (f *testRuntimeRunner) ValidateJSON(_ []byte) error { return nil }

func (f *testRuntimeRunner) ConfigureAccounting(_ *runtimestate.Store, u []auth.User) error {
	f.users = u
	return nil
}
func (f *testRuntimeRunner) ReloadReason(b []byte, _ string) error {
	if f.failNext {
		f.failNext = false
		return errors.New("reload failed")
	}
	f.configs = append(f.configs, append([]byte(nil), b...))
	f.closed = false
	return nil
}

func TestRuntimeReloadFailureRollsBackPersistedCandidateAndLease(t *testing.T) {
	r, runner, p := runtimeFixture(t)
	commitFixture(t, r, p)
	confirmed, revision := r.confirmed, r.revision
	r.now = func() time.Time { return confirmed.Add(time.Minute) }
	runner.failNext = true
	p.Users = nil
	raw, _ := json.Marshal(p)
	if err := r.commitCandidate(p, r.now(), raw); err == nil {
		t.Fatal("failed reload acknowledged")
	}
	saved, err := r.state.LoadSnapshot()
	if err != nil || !saved.ConfirmedAt.Equal(confirmed) || saved.Revision != revision {
		t.Fatal("old durable lease not restored", saved, err)
	}
	if runner.closed || r.fault || len(r.users) != 1 {
		t.Fatal("old usable authorization lost")
	}
}

func TestRuntimeCrashAfterPersistenceReplaysConfirmedCandidate(t *testing.T) {
	r, _, p := runtimeFixture(t)
	path := filepath.Join(t.TempDir(), "crash.db")
	store, err := runtimestate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	r.state = store
	confirmed := r.now()
	r.saveSnapshot = func(s runtimestate.Snapshot, limits []runtimestate.QuotaLimit) error {
		if err := store.SaveSnapshot(s, limits); err != nil {
			return err
		}
		panic("simulated process crash before reload")
	}
	raw, _ := json.Marshal(p)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("crash hook not reached")
			}
		}()
		_ = r.commitCandidate(p, confirmed, raw)
	}()
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := runtimestate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reopened.Close() }()
	saved, err := reopened.LoadSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeRuntimeSnapshot(saved, runtimeFingerprint(r.spec), confirmed.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	r.state, r.users, r.nodes, r.limits, r.confirmed, r.revision = reopened, decoded.users(), decoded.Nodes, decoded.Limits, saved.ConfirmedAt, saved.Revision
	r.now = func() time.Time { return confirmed.Add(time.Hour) }
	if err := r.runner.ConfigureAccounting(reopened, r.users); err != nil {
		t.Fatal(err)
	}
	if err := r.apply("restart confirmed desired state", true); err != nil {
		t.Fatal(err)
	}
	if len(r.lastApplied) != 2 || !r.confirmed.Equal(confirmed) {
		t.Fatal("restart lost aliases or extended authorization")
	}
	for _, user := range r.lastApplied {
		if user.EffectiveExitID != "a" {
			t.Fatal("persisted candidate not activated", user.EffectiveExitID)
		}
	}
}
func (f *testRuntimeRunner) Status() proxy.ReloadStatus { return proxy.ReloadStatus{} }
func (f *testRuntimeRunner) Close() error               { f.closed = true; return nil }

func runtimeFixture(t *testing.T) (*bridgeRuntime, *testRuntimeRunner, runtimeSnapshotV1) {
	t.Helper()
	store, e := runtimestate.Open(filepath.Join(t.TempDir(), "state.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now().UTC()
	strat, e := mimic.New("apijson")
	if e != nil {
		t.Fatal(e)
	}
	spec := &config.Spec{
		Role:          config.RoleBridge,
		DevMode:       true,
		ListenAddress: "127.0.0.1",
		VLESSPort:     10443,
		SplitRouting:  config.BoolPtr(false),
	}
	runner := &testRuntimeRunner{}
	r := &bridgeRuntime{
		state:        store,
		runner:       runner,
		spec:         spec,
		strategy:     strat,
		logLevel:     "error",
		log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:          func() time.Time { return now },
		applications: &auth.RouteApplications{},
		selector:     exits.NewSelector(nil),
	}
	pref := "a"
	u := auth.User{
		UUID:      "2784871e-d8a9-4e1f-b831-3d86aa8653ee",
		AccountID: "account",
		IsActive:  true,
		Routes:    []auth.RouteCredential{{UUID: "3b7d2c48-cc5c-4ae4-b054-2dd59ce9e27b", ExitID: &pref}},
	}
	nodes := []exits.Node{
		{ID: "a", Enabled: true, Priority: 100, Address: "127.0.0.1", Port: 51001, TunnelUUID: "11111111-2222-3333-4444-555555555555"},
		{ID: "b", Enabled: true, Priority: 200, Address: "127.0.0.1", Port: 51002, TunnelUUID: "11111111-2222-3333-4444-555555555555"},
	}
	limits := []runtimestate.QuotaLimit{}
	for _, n := range nodes {
		for _, id := range []string{"account", ""} {
			limits = append(
				limits,
				runtimestate.QuotaLimit{
					AccountID:  id,
					ExitID:     n.ID,
					Period:     now.Format("2006-01"),
					LimitBytes: 1024 * 1024,
					ExpiresAt:  now.Add(runtimeLease),
				},
			)
		}
	}
	return r, runner, runtimeSnapshotV1{
		Version:     1,
		Fingerprint: runtimeFingerprint(spec),
		Users:       snapshotUsers([]auth.User{u}),
		Nodes:       nodes,
		Limits:      limits,
	}
}
func commitFixture(t *testing.T, r *bridgeRuntime, p runtimeSnapshotV1) {
	t.Helper()
	raw, e := json.Marshal(p)
	if e != nil {
		t.Fatal(e)
	}
	if e = r.commitCandidate(p, r.now(), raw); e != nil {
		t.Fatal(e)
	}
}

func TestRuntimeSaveFailureRestoresRunningDurableAuthorization(t *testing.T) {
	r, runner, p := runtimeFixture(t)
	commitFixture(t, r, p)
	original := append([]byte(nil), runner.configs[len(runner.configs)-1]...)
	confirmed := r.confirmed
	revision := r.revision
	r.now = func() time.Time { return confirmed.Add(time.Minute) }
	p.Users = nil
	r.saveSnapshot = func(runtimestate.Snapshot, []runtimestate.QuotaLimit) error { return errors.New("disk full") }
	raw, _ := json.Marshal(p)
	if e := r.commitCandidate(p, r.now(), raw); e == nil {
		t.Fatal("accepted failed persistence")
	}
	if runner.closed || r.fault || r.confirmed != confirmed || r.revision != revision {
		t.Fatalf("rollback state: closed=%v fault=%v confirmed=%v revision=%v", runner.closed, r.fault, r.confirmed, r.revision)
	}
	var originalConfig, restoredConfig any
	_ = json.Unmarshal(original, &originalConfig)
	_ = json.Unmarshal(runner.configs[len(runner.configs)-1], &restoredConfig)
	if !reflect.DeepEqual(originalConfig, restoredConfig) {
		for key, old := range originalConfig.(map[string]any) {
			if !reflect.DeepEqual(old, restoredConfig.(map[string]any)[key]) {
				t.Errorf("configuration field %s changed: old=%v restored=%v", key, old, restoredConfig.(map[string]any)[key])
			}
		}
	}
	cached, e := r.state.LoadSnapshot()
	if e != nil || cached.ConfirmedAt != confirmed || cached.Revision != revision {
		t.Fatal("durable confirmation changed", cached, e)
	}
	if !r.applications.Pending() {
		t.Fatal("failed candidate reported applied")
	}
	// Retrying the original state must clear the rejected update without
	// restarting an already correct core, and acknowledge the new revision.
	r.saveSnapshot = nil
	p.Users = snapshotUsers(r.users)
	before := len(runner.configs)
	commitFixture(t, r, p)
	if r.applications.Pending() || r.appliedRevision != r.revision {
		t.Fatal("successful unchanged state did not clear failed application")
	}
	if len(runner.configs) != before {
		t.Fatal("unchanged retry restarted core")
	}
}

func TestRuntimeLeasePersistsPrivateRoutesAndDoesNotExtendAtRestart(t *testing.T) {
	r, runner, p := runtimeFixture(t)
	commitFixture(t, r, p)
	cached, e := r.state.LoadSnapshot()
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := decodeRuntimeSnapshot(cached, runtimeFingerprint(r.spec), cached.ConfirmedAt.Add(23*time.Hour))
	if e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(decoded.users(), p.users()) {
		t.Fatal("private owner or routing fields lost")
	}
	if _, e = decodeRuntimeSnapshot(cached, runtimeFingerprint(r.spec), cached.ConfirmedAt.Add(24*time.Hour)); e == nil {
		t.Fatal("expired restart authorized")
	}
	r.now = func() time.Time { return cached.ConfirmedAt.Add(24 * time.Hour) }
	if e = r.apply("lease deadline", true); e == nil || !runner.closed {
		t.Fatal("expired running VPN not closed")
	}
}

func TestRuntimeQuotaExhaustionFallsBackWithoutControlDatabase(t *testing.T) {
	r, _, p := runtimeFixture(t)
	commitFixture(t, r, p)
	if _, e := r.state.Reserve("account", "a", 256*1024); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 3; i++ {
		if _, e := r.state.Reserve("account", "a", 256*1024); e != nil {
			t.Fatal(e)
		}
	}
	if e := r.apply("local quota", false); e != nil {
		t.Fatal(e)
	}
	for _, u := range r.lastApplied {
		if u.EffectiveExitID != "b" {
			t.Fatal("quota bypass or no fallback", u.EffectiveExitID)
		}
	}
	for i := 0; i < 4; i++ {
		if _, e := r.state.Reserve("account", "b", 256*1024); e != nil {
			t.Fatal(e)
		}
	}
	if e := r.apply("all quotas exhausted", false); e != nil {
		t.Fatal(e)
	}
	for _, u := range r.lastApplied {
		if u.EffectiveExitID != auth.BlockedExit {
			t.Fatal("exhausted backup allowed", u.EffectiveExitID)
		}
	}
}

func TestRuntimeFailoverDoesNotWaitForControlRefresh(t *testing.T) {
	r, _, p := runtimeFixture(t)
	commitFixture(t, r, p)
	r.selector = exits.NewSelector(func(_ context.Context, n exits.Node) exits.Health { return exits.Health{InternetOK: n.ID == "b"} })
	r.selector.SetActiveID("a")
	// A wedged SQL operation holds only the control lock. Neither measurements
	// nor applying an exit selection can wait for it.
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 2; i++ {
			r.selector.ProbeAndSelect(context.Background(), p.Nodes)
		}
		done <- r.apply("exit failure during SQL outage", false)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("local failover waits for control refresh")
	}
	for _, user := range r.lastApplied {
		if user.EffectiveExitID != "b" {
			t.Fatal("unhealthy preferred exit retained", user.EffectiveExitID)
		}
	}
}
