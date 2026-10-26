package deployansible

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type preparedLifecycleHandoff struct {
	Schema    int    `json:"schema"`
	Source    string `json:"source_id"`
	Operation string `json:"operation_id"`
	Binding   string `json:"request_sha256"`
}

// ReservePreparedLifecycle seeds only the already planned recovery upgrade.
// The caller must authenticate stopped dispatch origins and enforcement proof
// before calling, and retain this operation lease through the broker handshake.
// This is not a CLI override or a way to clear an uncertain execution fence.
func ReservePreparedLifecycle(ctx context.Context, directory, sourceID, operationID, binding string) error {
	fail := errors.New("recovery_lifecycle_handoff_unverified")
	lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease)
	if !ok || lease.directory != directory || !jobID.MatchString(sourceID) || !jobID.MatchString(operationID) ||
		sourceID == operationID || len(binding) != 64 || strings.Trim(binding, "0123456789abcdef") != "" {
		return fail
	}
	lease.run.Lock()
	defer lease.run.Unlock()
	if !lease.active.Load() {
		return fail
	}
	admission, err := controllerLock(filepath.Join(directory, "execution-admission.lock"))
	if err != nil {
		return fail
	}
	defer admission.Close() //nolint:errcheck
	fence, err := inspectExecutionFence(directory)
	if err != nil || fence != nil {
		return ErrExecutionFenced
	}
	gate, err := openLifecycleGate(directory)
	if err != nil {
		return fail
	}
	defer gate.close()
	want := preparedLifecycleHandoff{1, sourceID, operationID, binding}
	path := filepath.Join(directory, "preparation-lifecycle-handoff.json")
	raw, err := readRetryPrivate(path)
	if err == nil {
		var saved preparedLifecycleHandoff
		if json.Unmarshal(raw, &saved) != nil || saved != want {
			return fail
		}
	} else if os.IsNotExist(err) {
		// Publish the exact source before changing lifecycle.json. A crash here
		// can only resume this same metadata transaction, never another ID.
		if gate.current.ID != sourceID || gate.current.Phase != "released" || gate.retired[operationID] {
			return fail
		}
		raw, _ = json.Marshal(want)
		if _, err = gate.savePrivateJSON(filepath.Base(path), raw); err != nil {
			return fail
		}
	} else {
		return fail
	}
	if (gate.current.ID != sourceID || gate.current.Phase != "released") &&
		(gate.current.ID != operationID || gate.current.Phase != "applying") {
		return fail
	}
	response := gate.transitionWithLock(operationID, "applying", lease.file)
	if response.Code != "" || response.State != "applying" {
		return fail
	}
	return nil
}
