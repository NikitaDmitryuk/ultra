package cloud

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestRetryCreatesAttemptOnlyForFailedInstallation(t *testing.T) {
	for _, test := range []struct {
		state, phase  string
		attempt, want uint64
		conflict      bool
	}{
		{"failed", "install", 0, 1, false},
		{"failed", "install", 1, 2, false},
		{"unknown", "creating", 2, 2, false},
		{"failed", "prepare", 2, 2, false},
		{"failed", "verify", 2, 2, false},
		{"failed", "publish", 2, 2, false},
		{"ready", "install", 2, 2, true},
		{"pending", "install", 2, 2, true},
		{"failed", "install", ^uint64(0), ^uint64(0), true},
	} {
		t.Run(test.state+"/"+test.phase, func(t *testing.T) {
			s, provider, _ := testService()
			store := s.Store.(*memoryStore)
			op := Operation{
				ID:             "purchase",
				State:          test.state,
				Phase:          test.phase,
				InstallAttempt: test.attempt,
				InstanceID:     "vm",
				ExitID:         "exit",
				FirewallID:     "firewall",
				Charged:        true,
			}
			store.ops[op.ID] = op
			err := s.Action(context.Background(), 1, op.ID, "retry")
			if test.conflict != errors.Is(err, ErrConflict) || (err != nil && !test.conflict) {
				t.Fatalf("retry: %v", err)
			}
			saved := store.ops[op.ID]
			if saved.InstallAttempt != test.want || saved.Phase != op.Phase || saved.InstanceID != op.InstanceID ||
				saved.ExitID != op.ExitID ||
				saved.FirewallID != op.FirewallID ||
				!saved.Charged {
				t.Fatalf("retry changed purchase or wrong attempt: %#v", saved)
			}
			if provider.creates != 0 {
				t.Fatal("retry purchased another VM")
			}
			if test.conflict && !reflect.DeepEqual(saved, op) {
				t.Fatal("rejected retry changed operation")
			}
		})
	}
}
