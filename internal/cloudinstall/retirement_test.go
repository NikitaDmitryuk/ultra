package cloudinstall

import (
	"context"
	"errors"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
)

func TestRetirementProtectsBridgeAndMainBeforeDatabaseMutation(t *testing.T) {
	p := &Provisioner{DB: &db.DB{}, Bridge: &config.Spec{Database: &config.DatabaseSpec{PrimaryHost: "192.0.2.3"}}, BridgeIP: "192.0.2.1"}
	p.Bridge.Exit.Address = "192.0.2.2"
	for _, address := range []string{"192.0.2.1", "192.0.2.2", "::ffff:192.0.2.2", "192.0.2.3"} {
		if err := p.ValidateRetirement(context.Background(), &cloud.Operation{ID: "operation", ExitID: "operation"}, cloud.Instance{IP: address}); !errors.Is(err, cloud.ErrConflict) {
			t.Fatalf("protected address %s accepted: %v", address, err)
		}
	}
}

func TestRetirementRequiresPersistedInfrastructure(t *testing.T) {
	p := &Provisioner{}
	if err := p.ValidateRetirement(context.Background(), &cloud.Operation{}, cloud.Instance{IP: "192.0.2.2"}); !errors.Is(err, cloud.ErrUnavailable) {
		t.Fatal(err)
	}
}

func TestRetirementRequiresKnownPrimaryIdentity(t *testing.T) {
	for _, primary := range []string{"", "db.example.test", "192.0.2.999"} {
		t.Run(primary, func(t *testing.T) {
			p := &Provisioner{DB: &db.DB{}, Bridge: &config.Spec{Database: &config.DatabaseSpec{PrimaryHost: primary}}}
			if err := p.ValidateRetirement(context.Background(), &cloud.Operation{}, cloud.Instance{IP: "192.0.2.2"}); !errors.Is(err, cloud.ErrUnavailable) {
				t.Fatalf("retirement accepted unknown primary %q: %v", primary, err)
			}
		})
	}
}

func TestRetirementRechecksSavedInfrastructureAddressWithoutProvider(t *testing.T) {
	p := &Provisioner{DB: &db.DB{}, Bridge: &config.Spec{Database: &config.DatabaseSpec{PrimaryHost: "192.0.2.3"}}, BridgeIP: "192.0.2.1"}
	p.Bridge.Exit.Address = "192.0.2.2"
	for _, phase := range []string{"retire_unpublish", "retire_delete", "retire_cleanup"} {
		for _, address := range []string{"", "192.0.2.1", "192.0.2.2", "192.0.2.3"} {
			op := &cloud.Operation{ID: "operation", Phase: phase, RetirementTarget: address}
			if err := p.ValidateRetirement(context.Background(), op, cloud.Instance{}); !errors.Is(err, cloud.ErrConflict) {
				t.Fatalf("saved protected address %q in %s accepted: %v", address, phase, err)
			}
		}
	}
}
