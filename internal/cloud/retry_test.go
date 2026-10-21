package cloud

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestReinstallOnlyRecoversFailedStagedIdentity(t *testing.T) {
	for _, state := range []string{"failed", "ready", "pending", "unknown"} {
		for _, phase := range []string{"verify", "install", "prepare", "publish", "cleanup"} {
			s, provider, _ := testService()
			store := s.Store.(*memoryStore)
			op := Operation{ID: "purchase", ExitID: "purchase", InstanceID: "vm", State: state, Phase: phase, Charged: true}
			store.ops[op.ID] = op
			err := s.Action(context.Background(), 1, op.ID, "reinstall")
			accepted := state == "failed" && phase == "verify"
			if accepted != (err == nil) {
				t.Fatalf("%s/%s: %v", state, phase, err)
			}
			saved := store.ops[op.ID]
			if accepted {
				if saved.Phase != "install" || saved.State != "pending" || !saved.Reinstall || saved.InstallAttempt != 1 ||
					saved.InstanceID != op.InstanceID ||
					saved.ExitID != op.ExitID ||
					!saved.Charged {
					t.Fatal("reinstall changed purchase identity")
				}
			} else if !reflect.DeepEqual(saved, op) {
				t.Fatal("rejected reinstall changed operation")
			}
			if provider.creates != 0 {
				t.Fatal("reinstall bought another VM")
			}
		}
	}
}

func TestReinstallRejectsUnboundOrProtectedIdentity(t *testing.T) {
	for _, kind := range []string{"node", "instance", "ingress", "generation"} {
		s, _, _ := testService()
		store := s.Store.(*memoryStore)
		op := Operation{ID: "purchase", ExitID: "purchase", InstanceID: "vm", State: "failed", Phase: "verify"}
		switch kind {
		case "node":
			op.ExitID = "other"
		case "instance":
			op.InstanceID = ""
		case "ingress":
			s.IngressInstanceID = op.InstanceID
		case "generation":
			op.InstallAttempt = ^uint64(0)
		}
		store.ops[op.ID] = op
		if err := s.Action(context.Background(), 1, op.ID, "reinstall"); !errors.Is(err, ErrConflict) {
			t.Fatalf("%s: %v", kind, err)
		}
		if !reflect.DeepEqual(store.ops[op.ID], op) {
			t.Fatal("rejected reinstall changed operation")
		}
	}
}

func TestOutstandingReinstallRetryRetainsJobAndBlocksUnprovenDelete(t *testing.T) {
	for _, jobID := range []string{"", "job"} {
		s, _, _ := testService()
		store := s.Store.(*memoryStore)
		op := Operation{
			ID:              "purchase",
			ExitID:          "purchase",
			InstanceID:      "vm",
			State:           "failed",
			Phase:           "install",
			Reinstall:       true,
			InstallAttempt:  3,
			ReinstallJobID:  jobID,
			ReinstallTarget: "192.0.2.2",
		}
		store.ops[op.ID] = op
		if err := s.Action(context.Background(), 1, op.ID, "delete"); !errors.Is(err, ErrConflict) {
			t.Fatal("delete escaped outstanding receipt", err)
		}
		if err := s.Action(context.Background(), 1, op.ID, "retry"); err != nil {
			t.Fatal(err)
		}
		saved := store.ops[op.ID]
		if saved.InstallAttempt != op.InstallAttempt || saved.ReinstallJobID != op.ReinstallJobID ||
			saved.ReinstallTarget != op.ReinstallTarget ||
			saved.State != "pending" {
			t.Fatal("retry abandoned outstanding worker identity")
		}
	}
}

func TestRetryCreatesAttemptOnlyForFailedInstallation(t *testing.T) {
	for _, test := range []struct {
		state, phase  string
		attempt, want uint64
		conflict      bool
	}{
		{"failed", "install", 0, 1, false},
		{"failed", "install", 1, 2, false},
		{"unknown", "creating", 2, 2, true},
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
