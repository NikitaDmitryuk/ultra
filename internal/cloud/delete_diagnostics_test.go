package cloud

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type refusedUnpublish struct {
	*fakeProvisioner
	err error
}

func (p refusedUnpublish) Unpublish(context.Context, *Operation) error { return p.err }

func TestDeleteRouteRemovalFailurePreventsProviderDelete(t *testing.T) {
	for _, last := range []bool{false, true} {
		t.Run(map[bool]string{false: "unknown", true: "last_enabled"}[last], func(t *testing.T) {
			service, provider, provisioner := testService()
			cause := errors.New("private-token=do-not-retain")
			if last {
				cause = errors.Join(ErrLastEnabledExit, cause)
			}
			service.Provisioner = refusedUnpublish{provisioner, cause}
			store := service.Store.(*memoryStore)
			store.ops["op"] = Operation{ID: "op", ExitID: "exit", InstanceID: "vm", State: "ready", Phase: "ready", Charged: true}
			ctx := context.Background()
			if err := service.Action(ctx, 1, "op", "delete"); err != nil {
				t.Fatal(err)
			}
			if provider.deletes != 0 {
				t.Fatal("request deleted VPS before unpublish")
			}
			if err := service.Step(ctx); !errors.Is(err, cause) {
				t.Fatalf("worker error = %v", err)
			}
			op := store.ops["op"]
			if op.Error != "route_removal_failed" || op.State != "failed" || op.Phase != "unpublish" || !op.Charged || provider.deletes != 0 {
				t.Fatalf("unsafe deletion result: %+v, provider deletes %d", op, provider.deletes)
			}
			if op.ErrorMessage == "" || strings.Contains(op.ErrorMessage, "private-token") {
				t.Fatalf("unsafe diagnostic: %q", op.ErrorMessage)
			}
			if last && !strings.Contains(op.ErrorMessage, "Нельзя удалить последний включённый exit") {
				t.Fatalf("missing last-exit explanation: %q", op.ErrorMessage)
			}
		})
	}
}
