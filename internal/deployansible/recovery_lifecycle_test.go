package deployansible

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestPreparedLifecycleHandoffRequiresLeaseAndBindsSource(t *testing.T) {
	root := lifecycleTestDirectory(t)
	source, operation := uuid.NewString(), uuid.NewString()
	raw, _ := json.Marshal(lifecycleState{ID: source, Phase: "released"})
	if err := os.WriteFile(filepath.Join(root, "lifecycle.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	binding := strings.Repeat("a", 64)
	if err := ReservePreparedLifecycle(context.Background(), root, source, operation, binding); err == nil {
		t.Fatal("unleased reservation accepted")
	}
	ctx, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	for range 2 {
		if err = ReservePreparedLifecycle(ctx, root, source, operation, binding); err != nil {
			t.Fatal(err)
		}
	}
	if err = ReservePreparedLifecycle(ctx, root, source, uuid.NewString(), binding); err == nil {
		t.Fatal("different operation stole prepared reservation")
	}
	if err = ReservePreparedLifecycle(ctx, root, uuid.NewString(), operation, binding); err == nil {
		t.Fatal("historical source changed during replay")
	}
	if err = ReservePreparedLifecycle(ctx, root, source, operation, strings.Repeat("b", 64)); err == nil {
		t.Fatal("different coordinator request accepted")
	}
	gate, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	if !gate.blocked() || gate.current.ID != operation {
		t.Fatal("new broker startup did not retain topology gate")
	}
}

func TestPreparedLifecycleHandoffDoesNotClearExecutionFence(t *testing.T) {
	root := lifecycleTestDirectory(t)
	source, operation := uuid.NewString(), uuid.NewString()
	raw, _ := json.Marshal(lifecycleState{ID: source, Phase: "released"})
	if err := os.WriteFile(filepath.Join(root, "lifecycle.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	fence := []byte(`{"schema_version":1,"generation":"` + strings.Repeat("a", 32) + `","job_directory":"/an/uncertain/job"}`)
	if err = os.WriteFile(filepath.Join(root, "execution-fence.json"), fence, 0600); err != nil {
		t.Fatal(err)
	}
	if err = ReservePreparedLifecycle(ctx, root, source, operation, strings.Repeat("a", 64)); err != ErrExecutionFenced {
		t.Fatalf("uncertain execution admitted: %v", err)
	}
	if _, err = os.Stat(filepath.Join(root, "preparation-lifecycle-handoff.json")); !os.IsNotExist(err) {
		t.Fatal("handoff intent published over uncertain execution")
	}
}
