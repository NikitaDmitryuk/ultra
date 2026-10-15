package main

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/runtimestate"
)

func proofRun(t *testing.T, args ...string) error {
	t.Helper()
	oldFlags, oldArgs := flag.CommandLine, os.Args
	flag.CommandLine = flag.NewFlagSet("state-proof", flag.ContinueOnError)
	os.Args = append([]string{"state-proof"}, args...)
	defer func() { flag.CommandLine, os.Args = oldFlags, oldArgs }()
	return run()
}

func TestProofDetectsAllowanceIncreaseAfterStoppedRestart(t *testing.T) {
	path, baseline := filepath.Join(t.TempDir(), "state.db"), filepath.Join(t.TempDir(), "baseline.json")
	now := time.Now().UTC()
	limits := []runtimestate.QuotaLimit{
		{
			AccountID:  "fixture",
			ExitID:     "exit",
			Period:     now.Format("2006-01"),
			LimitBytes: runtimestate.ReservationChunk * 4,
			ExpiresAt:  now.Add(time.Hour),
		},
		{ExitID: "exit", Period: now.Format("2006-01"), LimitBytes: runtimestate.ReservationChunk * 4, ExpiresAt: now.Add(time.Hour)},
	}
	raw, err := json.Marshal(struct {
		Limits []runtimestate.QuotaLimit `json:"limits"`
	}{limits})
	if err != nil {
		t.Fatal(err)
	}
	store, err := runtimestate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SaveSnapshot(runtimestate.Snapshot{ConfirmedAt: now, Payload: raw}, limits); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if err = proofRun(t, "-state", path, "-baseline", baseline); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(baseline)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("baseline must remain private", err)
	}
	store, err = runtimestate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.Reserve("fixture", "exit", 1); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	if err = proofRun(t, "-state", path, "-baseline", baseline, "-compare"); err != nil {
		t.Fatal("spent quota rejected", err)
	}
	if err = os.WriteFile(baseline, []byte(`{"fixture/exit":0,"/exit":0}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err = proofRun(t, "-state", path, "-baseline", baseline, "-compare"); err == nil {
		t.Fatal("increased allowance accepted")
	}
	if err = os.Chmod(baseline, 0644); err != nil {
		t.Fatal(err)
	}
	if err = proofRun(t, "-state", path, "-baseline", baseline, "-compare"); err == nil {
		t.Fatal("public baseline accepted")
	}
	link := filepath.Join(t.TempDir(), "journal-link")
	if err = os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err = proofRun(t, "-state", link, "-baseline", baseline, "-compare"); err == nil {
		t.Fatal("symlink journal accepted")
	}
}
