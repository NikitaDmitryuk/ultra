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

func assertRetiredLifecycle(t *testing.T, gate *lifecycleGate, id string) {
	t.Helper()
	for _, phase := range []string{"applying", "checking", "released"} {
		if result := gate.transition(id, phase); result.Code != "lifecycle_retired" {
			t.Fatalf("retired %s accepted: %+v", phase, result)
		}
	}
	if result := gate.transitionWithLock(id, "applying", nil, true); result.Code != "lifecycle_retired" {
		t.Fatal("retired resume accepted", result)
	}
	if result := gate.attach(id); result.Code != "lifecycle_retired" {
		closeInputs(result.leaseOutputs)
		t.Fatal("retired attachment accepted", result)
	}
}

func TestLifecycleRetirementPersistsAcrossRestartAndNewOperations(t *testing.T) {
	root := lifecycleTestDirectory(t)
	gate, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	id := "11111111-2222-3333-4444-555555555555"
	other := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if result := gate.retire(id); result.Code != "lifecycle_not_owned" {
		t.Fatal("unreserved operation retired", result)
	}
	if result := gate.transition(id, "applying"); result.Code != "" {
		t.Fatal(result)
	}
	if result := gate.retire(other); result.Code != "lifecycle_not_owned" || !gate.blocked() {
		t.Fatal("mismatched retirement changed reservation", result)
	}
	if result := gate.retire(id); result.Code != "" || result.State != "released" || gate.blocked() {
		t.Fatal(result)
	}
	info, err := os.Lstat(filepath.Join(root, "lifecycle-retired.json"))
	if err != nil || info.Mode().Perm() != 0600 || !ownedByProcess(info) {
		t.Fatal("retirement journal is not private", err)
	}
	gate.close()
	gate, err = openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	assertRetiredLifecycle(t, gate, id)
	if result := gate.retire(id); result.Code != "" {
		t.Fatal("idempotent retirement failed", result)
	}
	if result := gate.transition(other, "applying"); result.Code != "" {
		t.Fatal("new operation blocked after retirement", result)
	}
	assertRetiredLifecycle(t, gate, id)
	if result := gate.retire(id); result.Code != "" || gate.current.ID != other || !gate.blocked() {
		t.Fatal("repeated retirement released newer reservation", result)
	}
	if result := gate.retire(other); result.Code != "" {
		t.Fatal(result)
	}
	gate.close()
	gate, err = openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	assertRetiredLifecycle(t, gate, id)
	assertRetiredLifecycle(t, gate, other)
}

func TestLifecycleRetirementWaitsForSurvivingOperatorAndRestarts(t *testing.T) {
	root := lifecycleTestDirectory(t)
	ctx, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	gate, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	id := "11111111-2222-3333-4444-555555555555"
	other := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if result := gate.transitionWithLock(id, "applying", ctx.Value(operationLeaseKey{}).(*operationLease).file); result.Code != "" {
		t.Fatal(result)
	}
	if result := gate.retire(id); result.Code != "infrastructure_busy" || !gate.blocked() {
		t.Fatal("surviving operator reservation released", result)
	}
	// This is the crash window after the tombstone is durable and before the
	// applying journal can be closed. Restart must permit only retirement.
	gate.close()
	gate, err = openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	assertRetiredLifecycle(t, gate, id)
	if result := gate.transition(other, "applying"); result.Code != "lifecycle_busy" {
		t.Fatal("new operation bypassed interrupted retirement", result)
	}
	if lock, err := gate.jobLock("configure-replica"); err == nil {
		_ = lock.Close()
		t.Fatal("maintenance bypassed interrupted retirement")
	}
	if result := gate.retire(id); result.Code != "infrastructure_busy" {
		t.Fatal(result)
	}
	release()
	if result := gate.transition(other, "applying"); result.Code != "lifecycle_busy" {
		t.Fatal("descriptor closure alone released reservation", result)
	}
	if result := gate.retire(id); result.Code != "" {
		t.Fatal("retirement retry failed", result)
	}
	if result := gate.transition(other, "applying"); result.Code != "" {
		t.Fatal(result)
	}
}

func TestLifecycleRetirementRejectsCheckingAndInvalidIDs(t *testing.T) {
	gate, err := openLifecycleGate(lifecycleTestDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	if result := gate.retire("../bad"); result.Code != "invalid_operation_id" {
		t.Fatal(result)
	}
	id := "11111111-2222-3333-4444-555555555555"
	for _, phase := range []string{"applying", "checking"} {
		if result := gate.transition(id, phase); result.Code != "" {
			t.Fatal(result)
		}
	}
	if result := gate.retire(id); result.Code != "lifecycle_not_owned" || !gate.blocked() {
		t.Fatal("checking operation retired", result)
	}
}

func TestLifecycleRejectsUnsafeRetirementJournal(t *testing.T) {
	id := "11111111-2222-3333-4444-555555555555"
	for _, raw := range []string{
		`{}`, `null`, `{"version":2,"ids":[]}`, `{"version":1,"ids":null}`,
		`{"version":1,"ids":["invalid"]}`, `{"version":1,"ids":[],"future":true}`,
		`{"version":1,"ids":[]} {}`, `{"version":1,"ids":["` + id + `","` + id + `"]}`,
	} {
		t.Run(raw, func(t *testing.T) {
			root := lifecycleTestDirectory(t)
			if err := os.WriteFile(filepath.Join(root, "lifecycle-retired.json"), []byte(raw), 0600); err != nil {
				t.Fatal(err)
			}
			if gate, err := openLifecycleGate(root); err == nil {
				gate.close()
				t.Fatal("malformed retirement journal accepted")
			}
		})
	}
	for _, kind := range []string{"public", "symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			root := lifecycleTestDirectory(t)
			path := filepath.Join(root, "lifecycle-retired.json")
			var err error
			switch kind {
			case "public":
				err = os.WriteFile(path, []byte(`{"version":1,"ids":[]}`), 0644)
			case "symlink":
				err = os.Symlink(filepath.Join(root, "missing"), path)
			case "directory":
				err = os.Mkdir(path, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if gate, err := openLifecycleGate(root); err == nil {
				gate.close()
				t.Fatal("unsafe retirement journal accepted")
			}
		})
	}
}

func TestLifecycleRetirementPersistenceFailureKeepsReservationClosed(t *testing.T) {
	root := lifecycleTestDirectory(t)
	gate, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	id := "11111111-2222-3333-4444-555555555555"
	if result := gate.transition(id, "applying"); result.Code != "" {
		t.Fatal(result)
	}
	// A directory in place of the journal makes the atomic rename fail.
	path := filepath.Join(root, "lifecycle-retired.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if result := gate.retire(id); result.Code != "lifecycle_persistence_failed" || !gate.blocked() || gate.lock == nil {
		t.Fatal("failed tombstone persistence released reservation", result)
	}
	assertRetiredLifecycle(t, gate, id)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if result := gate.retire(id); result.Code != "" {
		t.Fatal("retirement could not be retried", result)
	}
}

func lifecycleTestDirectory(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestLifecycleSupersessionPreservesLockAndRetiresOldID(t *testing.T) {
	root := lifecycleTestDirectory(t)
	ctx, release, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	lease := ctx.Value(operationLeaseKey{}).(*operationLease)
	gate, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	id := "11111111-2222-3333-4444-555555555555"
	next := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if result := gate.transitionWithLock(id, "applying", lease.file); result.Code != "" {
		t.Fatal(result)
	}
	for _, pair := range [][2]string{{next, id}, {id, id}, {"invalid", next}} {
		if result := gate.supersede(pair[0], pair[1], lease.file); result.Code == "" || gate.retired[id] {
			t.Fatal("mismatched handoff accepted", result)
		}
	}
	if result := gate.supersede(id, next, nil); result.Code != "lifecycle_attachment_failed" || gate.retired[id] {
		t.Fatal("missing handoff descriptor accepted", result)
	}
	foreign, err := controllerLock(filepath.Join(root, "other.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close() //nolint:errcheck
	if result := gate.supersede(id, next, foreign); result.Code != "lifecycle_attachment_failed" || gate.retired[id] {
		t.Fatal("foreign handoff descriptor accepted", result)
	}
	if result := gate.supersede(id, next, lease.file); result.Code != "" || gate.current.ID != next || !gate.blocked() {
		t.Fatal(result)
	}
	assertRetiredLifecycle(t, gate, id)
	if result := gate.supersede(id, next, lease.file); result.Code != "" {
		t.Fatal("idempotent handoff failed", result)
	}
	release()
	if lock, err := controllerLock(filepath.Join(root, "infrastructure.lock")); err == nil {
		_ = lock.Close()
		t.Fatal("handoff released infrastructure lock")
	}
	gate.close()
	gate, err = openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	assertRetiredLifecycle(t, gate, id)
	if gate.current.ID != next || gate.current.Phase != "applying" || !gate.blocked() {
		t.Fatal("restart lost successor reservation", gate.current)
	}
}

func TestLifecycleSupersessionReconcilesWriteAheadIntent(t *testing.T) {
	root := lifecycleTestDirectory(t)
	gate, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	id := "11111111-2222-3333-4444-555555555555"
	next := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if result := gate.transition(id, "applying"); result.Code != "" {
		t.Fatal(result)
	}
	// Emulate a crash after fsync of the tombstone + handoff intent, before
	// replacing the applying lifecycle journal. The old ID must never reopen.
	gate.retired[id] = true
	gate.handoff = &lifecycleHandoff{OldID: id, NewID: next}
	if err := gate.saveRetired(); err != nil {
		t.Fatal(err)
	}
	assertRetiredLifecycle(t, gate, id)
	if result := gate.retire(id); result.Code != "lifecycle_not_owned" {
		t.Fatal("retirement discarded pending successor", result)
	}
	if result := gate.transition(next, "applying"); result.Code != "lifecycle_busy" {
		t.Fatal("successor bypassed unfinished handoff", result)
	}
	gate.close()
	gate, err = openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	assertRetiredLifecycle(t, gate, id)
	if gate.current.ID != next || gate.current.Phase != "applying" || gate.lock == nil {
		t.Fatal("write-ahead handoff not reconciled", gate.current)
	}
	attached := gate.attach(next)
	defer closeInputs(attached.leaseOutputs)
	if attached.Code != "" {
		t.Fatal("successor could not attach", attached)
	}
}

func TestLifecycleSupersessionPersistenceFailureKeepsOldClosed(t *testing.T) {
	root := lifecycleTestDirectory(t)
	gate, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	id := "11111111-2222-3333-4444-555555555555"
	next := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if result := gate.transition(id, "applying"); result.Code != "" {
		t.Fatal(result)
	}
	path := filepath.Join(root, "lifecycle-retired.json")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if result := gate.supersede(id, next, gate.lock); result.Code != "lifecycle_persistence_failed" || gate.current.ID != id || gate.lock == nil || !gate.blocked() {
		t.Fatal("failed handoff released or changed reservation", result)
	}
	assertRetiredLifecycle(t, gate, id)
	if result := gate.transition(next, "applying"); result.Code != "lifecycle_busy" {
		t.Fatal(result)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if result := gate.supersede(id, next, gate.lock); result.Code != "" {
		t.Fatal("handoff retry failed", result)
	}
}

func TestLifecycleRejectsInconsistentRetirementState(t *testing.T) {
	id := "11111111-2222-3333-4444-555555555555"
	for _, phase := range []string{"missing", "checking"} {
		t.Run(phase, func(t *testing.T) {
			root := lifecycleTestDirectory(t)
			gate, err := openLifecycleGate(root)
			if err != nil {
				t.Fatal(err)
			}
			if phase == "checking" {
				if err := gate.save(lifecycleState{ID: id, Phase: phase}); err != nil {
					t.Fatal(err)
				}
			}
			gate.retired[id] = true
			if err := gate.saveRetired(); err != nil {
				t.Fatal(err)
			}
			gate.close()
			if reopened, err := openLifecycleGate(root); err == nil {
				reopened.close()
				t.Fatal("inconsistent retirement state accepted")
			}
		})
	}
}
