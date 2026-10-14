package deployansible

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestLifecyclePersistsLockAndCheckingTopologyGate(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	g, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	id := "11111111-2222-3333-4444-555555555555"
	other := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if r := g.transition(id, "applying"); r.Code != "" {
		t.Fatal(r)
	}
	if !g.blocked() {
		t.Fatal("topology remains open")
	}
	if lock, err := controllerLock(filepath.Join(root, "infrastructure.lock")); err == nil {
		_ = lock.Close()
		t.Fatal("external lifecycle escaped lock")
	}
	if r := g.transition(other, "released"); r.Code == "" {
		t.Fatal("another operation released lock")
	}
	g.close()
	// Restart restores the durable lock before any queued worker can start.
	g, err = openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	if _, err = g.jobLock("configure-replica"); err == nil {
		t.Fatal("maintenance ran during applying")
	}
	if r := g.transition(id, "checking"); r.Code != "" {
		t.Fatal(r)
	}
	if !g.blocked() {
		t.Fatal("checking released topology freeze")
	}
	if _, err = g.jobLock("configure-exit"); err == nil {
		t.Fatal("new topology ran during checking")
	}
	maintenance, err := g.jobLock("configure-replica")
	if err != nil {
		t.Fatal(err)
	}
	if r := g.transition(id, "applying"); r.Code != "infrastructure_busy" {
		t.Fatal("applying did not wait for running maintenance", r)
	}
	_ = maintenance.Close()
	if r := g.transition(id, "applying"); r.Code != "" {
		t.Fatal(r)
	}
	if r := g.transition(id, "released"); r.Code != "" {
		t.Fatal(r)
	}
	if g.blocked() {
		t.Fatal("release did not reopen topology")
	}
	if r := g.transition(id, "released"); r.Code != "" {
		t.Fatal("idempotent release failed", r)
	}
	worker, err := g.jobLock("configure-exit")
	if err != nil {
		t.Fatal(err)
	}
	_ = worker.Close()
}
func TestLifecycleRejectsUnsafeJournal(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "lifecycle.json")
	for _, raw := range []string{`{}`, `{"id":"11111111-2222-3333-4444-555555555555","phase":"future"}`} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if g, err := openLifecycleGate(root); err == nil {
			g.close()
			t.Fatal("invalid journal accepted")
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "missing"), path); err != nil {
		t.Fatal(err)
	}
	if _, err := openLifecycleGate(root); err == nil {
		t.Fatal("symlink journal accepted")
	}
}

func TestLifecycleAdoptsExistingBridgeLocalLease(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	g, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	_, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	// SCM_RIGHTS preserves this open-file-description; retaining it must not
	// attempt an independent flock which would conflict with our own operation.
	f, err := controllerLock(filepath.Join(root, "other.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close() //nolint:errcheck
	id := "11111111-2222-3333-4444-555555555555"
	if r := g.transitionWithLock(id, "applying", f); r.Code != "infrastructure_busy" {
		t.Fatal("foreign descriptor accepted", r)
	}
}

func TestLifecycleRetainedLockSurvivesOriginalDescriptorClosure(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	g, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	leased, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	lease := leased.Value(operationLeaseKey{}).(*operationLease)
	id := "11111111-2222-3333-4444-555555555555"
	if r := g.transitionWithLock(id, "applying", lease.file); r.Code != "" {
		t.Fatal(r)
	}
	release()
	if f, err := controllerLock(filepath.Join(root, "infrastructure.lock")); err == nil {
		_ = f.Close()
		t.Fatal("broker lost transferred flock")
	}
	if r := g.transition(id, "released"); r.Code != "" {
		t.Fatal(r)
	}
	f, err := controllerLock(filepath.Join(root, "infrastructure.lock"))
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

func TestLifecycleRestartAcceptsStillRunningLocalOwner(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	leased, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	lease := leased.Value(operationLeaseKey{}).(*operationLease)
	g, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	id := "11111111-2222-3333-4444-555555555555"
	if r := g.transitionWithLock(id, "applying", lease.file); r.Code != "" {
		t.Fatal(r)
	}
	g.close()
	restarted, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal("controller deadlocked behind surviving local owner", err)
	}
	defer restarted.close()
	if _, err := restarted.jobLock("configure-replica"); err == nil {
		t.Fatal("restart opened workers before reattachment")
	}
	if r := restarted.transitionWithLock(id, "applying", lease.file); r.Code != "" {
		t.Fatal(r)
	}
	if restarted.lock == nil {
		t.Fatal("same-ID resume skipped reattachment")
	}
}

func TestLifecycleResumeRequiresSameActiveOwner(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	gate, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	id := "11111111-2222-3333-4444-555555555555"
	if result := gate.transitionWithLock(id, "applying", nil, true); result.Code != "lifecycle_not_owned" {
		t.Fatal(result)
	}
	if result := gate.transition(id, "applying"); result.Code != "" {
		t.Fatal(result)
	}
	if result := gate.transition(id, "checking"); result.Code != "" {
		t.Fatal(result)
	}
	if result := gate.transitionWithLock("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "applying", nil, true); result.Code != "lifecycle_not_owned" {
		t.Fatal(result)
	}
	if result := gate.transitionWithLock(id, "applying", nil, true); result.Code != "" {
		t.Fatal(result)
	}
	if result := gate.transition(id, "released"); result.Code != "" {
		t.Fatal(result)
	}
	if result := gate.transitionWithLock(id, "applying", nil, true); result.Code != "lifecycle_not_owned" {
		t.Fatal(result)
	}
}

func TestLifecycleAttachmentResumesRetainedLockAfterOperatorCrash(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	leased, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	gate, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	id := "11111111-2222-3333-4444-555555555555"
	if result := gate.transitionWithLock(id, "applying", leased.Value(operationLeaseKey{}).(*operationLease).file); result.Code != "" {
		t.Fatal(result)
	}
	release()
	if _, unlock, err := WithOperationLock(context.Background(), root); err == nil {
		unlock()
		t.Fatal("operator exit released broker's reservation")
	}
	if result := gate.attach("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"); result.Code != "lifecycle_not_owned" {
		closeInputs(result.leaseOutputs)
		t.Fatal("foreign attempt attached", result)
	}
	attached := gate.attach(id)
	if attached.Code != "" || len(attached.leaseOutputs) != 1 {
		t.Fatal(attached)
	}
	retained, err := retainInfrastructureLock(attached.leaseOutputs[0], filepath.Join(root, "infrastructure.lock"))
	closeInputs(attached.leaseOutputs)
	if err != nil {
		t.Fatal(err)
	}
	if result := gate.transition(id, "released"); result.Code != "" {
		t.Fatal(result)
	}
	if _, unlock, err := WithOperationLock(context.Background(), root); err == nil {
		unlock()
		t.Fatal("attached caller lost its retained lock")
	}
	if err := retained.Close(); err != nil {
		t.Fatal(err)
	}
	_, unlock, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal("completed attempt did not release lock", err)
	}
	unlock()
	if result := gate.attach(id); result.Code != "lifecycle_not_owned" {
		closeInputs(result.leaseOutputs)
		t.Fatal("released attempt attached", result)
	}
}

func TestLifecycleCheckingAttachmentWaitsForMaintenanceLock(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	gate, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	id := "11111111-2222-3333-4444-555555555555"
	if result := gate.transition(id, "applying"); result.Code != "" {
		t.Fatal(result)
	}
	if result := gate.transition(id, "checking"); result.Code != "" {
		t.Fatal(result)
	}
	maintenance, err := gate.jobLock("configure-replica")
	if err != nil {
		t.Fatal(err)
	}
	if result := gate.attach(id); result.Code != "infrastructure_busy" {
		closeInputs(result.leaseOutputs)
		t.Fatal("attachment raced maintenance", result)
	}
	if err := maintenance.Close(); err != nil {
		t.Fatal(err)
	}
	attached := gate.attach(id)
	defer closeInputs(attached.leaseOutputs)
	if attached.Code != "" || gate.phase() != "applying" {
		t.Fatal("attachment did not reserve applying phase", attached)
	}
}
