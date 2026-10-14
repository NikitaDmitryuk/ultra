package cloud

import (
	"context"
	"errors"
	"testing"
)

func TestLifecycleGateKeepsPendingCloudOperationsUnchanged(t *testing.T) {
	store := newMemory()
	store.ops["old"] = Operation{ID: "old", State: "pending", Phase: "prepare"}
	service := Service{Store: store, TopologyReady: func(context.Context) error { return errors.New("lifecycle_busy") }}
	if err := service.Step(context.Background()); err == nil {
		t.Fatal("closed gate advanced cloud operation")
	}
	if op := store.ops["old"]; op.State != "pending" || op.Phase != "prepare" || op.Error != "" {
		t.Fatalf("paused operation was failed or advanced: %+v", op)
	}
	if err := service.Action(context.Background(), 1, "old", "delete"); err == nil {
		t.Fatal("delete escaped closed gate")
	}
}
