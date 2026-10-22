package main

import (
	"encoding/json"
	"testing"
)

func TestOperatorJournalNeverInfersCompletion(t *testing.T) {
	for _, record := range []string{
		`{}`, `{"mutator_dispatched":false}`, `{"mutator_dispatched":true,"stage":"upgrade"}`,
		`{"mutator_dispatched":true,"stage":"completed"}`, `{"receipt":null,"stage":"status"}`,
	} {
		got, err := classifyOperatorJournal([]byte(record), []byte("config"))
		if err != nil {
			t.Fatal(err)
		}
		if got.MayAbandon || got.State != "blocked_unknown" {
			t.Fatalf("invented proof: %+v", got)
		}
	}
}

func TestOperatorJournalRejectsAmbiguousAndUnboundInputs(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `{"stage":"upgrade","stage":"done"}`, `{"mutator_dispatched":"false"}`, `{"config_sha256":"other"}`} {
		if _, err := classifyOperatorJournal([]byte(raw), []byte("config")); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	raw, _ := json.Marshal(map[string]any{"config_sha256": digestSHA256([]byte("config")), "mutator_dispatched": true, "stage": "upgrade"})
	got, err := classifyOperatorJournal(raw, []byte("config"))
	if err != nil || got.MayAbandon || got.NextAction != "manual-deploy --forward-only (independent admission required)" {
		t.Fatalf("%+v %v", got, err)
	}
}
