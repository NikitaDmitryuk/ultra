package deployansible

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// lifecycleGate persists an operator's topology reservation independently of its
// SSH session. Applying holds the same flock as worker jobs; checking permits
// maintenance but keeps new topology changes closed. Only an explicit release
// by the same operation reopens the gate; there is deliberately no unsafe TTL.
type lifecycleGate struct {
	mu        sync.Mutex
	directory string
	current   lifecycleState
	lock      *os.File
	retired   map[string]bool
	handoff   *lifecycleHandoff
}
type lifecycleState struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
}

func openLifecycleGate(directory string) (*lifecycleGate, error) {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || !ownedByProcess(info) {
		return nil, errors.New("private lifecycle directory required")
	}
	g := &lifecycleGate{directory: directory, retired: make(map[string]bool)}
	if err := g.loadRetired(); err != nil {
		return nil, err
	}
	path := filepath.Join(directory, "lifecycle.json")
	info, err = os.Lstat(path)
	if os.IsNotExist(err) {
		if len(g.retired) != 0 || g.handoff != nil {
			return nil, errors.New("missing lifecycle retirement reservation")
		}
		return g, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !ownedByProcess(info) {
		return nil, errors.New("invalid lifecycle journal")
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &g.current) != nil || !jobID.MatchString(g.current.ID) ||
		(g.current.Phase != "applying" && g.current.Phase != "checking" && g.current.Phase != "released") {
		return nil, errors.New("invalid lifecycle journal")
	}
	if g.retired[g.current.ID] && g.current.Phase == "checking" {
		return nil, errors.New("invalid retired lifecycle phase")
	}
	if admission, fenceErr := recoveryAdmission(directory); fenceErr != nil {
		return g, nil // Durable recovery also fences startup reconciliation.
	} else {
		admission()
	}
	if h := g.handoff; h != nil && g.current.ID == h.OldID {
		if g.current.Phase != "applying" || g.retired[h.NewID] {
			return nil, errors.New("invalid pending lifecycle handoff")
		}
		// The durable intent fences the old ID even if the broker died before
		// replacing lifecycle.json. Complete the handoff before serving peers.
		if err := g.save(lifecycleState{ID: h.NewID, Phase: "applying"}); err != nil {
			return nil, err
		}
	}
	if g.current.Phase == "applying" {
		g.lock, err = controllerLock(filepath.Join(directory, "infrastructure.lock"))
		if err != nil && !controllerLockBusy(err) {
			return nil, errors.New("lifecycle lock unavailable")
		}
		// A still-running local operator may retain the original OFD across a
		// controller restart. Keep every worker gated and accept only its root
		// same-ID descriptor handoff; do not deadlock startup waiting for it.
	}
	return g, nil
}
func (g *lifecycleGate) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lock != nil {
		_ = g.lock.Close()
		g.lock = nil
	}
}
func (g *lifecycleGate) blocked() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	admission, err := recoveryAdmission(g.directory)
	if err != nil {
		return true
	}
	defer admission()
	return g.current.Phase == "applying" || g.current.Phase == "checking"
}
func (g *lifecycleGate) save(next lifecycleState) error {
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	renamed, err := g.savePrivateJSON("lifecycle.json", raw)
	if renamed {
		g.current = next
	}
	return err
}

// savePrivateJSON only returns success after both the file and its directory
// entry are durable. The controller holds the private state directory lock.
func (g *lifecycleGate) savePrivateJSON(base string, raw []byte) (bool, error) {
	f, err := os.CreateTemp(g.directory, ".lifecycle-")
	if err != nil {
		return false, err
	}
	name := f.Name()
	defer os.Remove(name) //nolint:errcheck
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return false, err
	}
	if err = os.Rename(name, filepath.Join(g.directory, base)); err != nil {
		return false, err
	}
	return true, syncDirectory(g.directory)
}

type lifecycleRetirements struct {
	Version int               `json:"version"`
	IDs     []string          `json:"ids"`
	Handoff *lifecycleHandoff `json:"handoff,omitempty"`
}
type lifecycleHandoff struct {
	OldID string `json:"old_id"`
	NewID string `json:"new_id"`
}

func (g *lifecycleGate) loadRetired() error {
	path := filepath.Join(g.directory, "lifecycle-retired.json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !ownedByProcess(info) {
		return errors.New("invalid lifecycle retirement journal")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var journal lifecycleRetirements
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&journal) != nil || journal.Version != 1 || journal.IDs == nil {
		return errors.New("invalid lifecycle retirement journal")
	}
	if decoder.Decode(new(any)) != io.EOF {
		return errors.New("invalid lifecycle retirement journal")
	}
	for _, id := range journal.IDs {
		if !jobID.MatchString(id) || g.retired[id] {
			return errors.New("invalid lifecycle retirement journal")
		}
		g.retired[id] = true
	}
	if h := journal.Handoff; h != nil {
		if !jobID.MatchString(h.OldID) || !jobID.MatchString(h.NewID) || h.OldID == h.NewID || !g.retired[h.OldID] {
			return errors.New("invalid lifecycle handoff journal")
		}
		g.handoff = h
	}
	return nil
}

func (g *lifecycleGate) saveRetired() error {
	ids := make([]string, 0, len(g.retired))
	for id := range g.retired {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	raw, err := json.Marshal(lifecycleRetirements{Version: 1, IDs: ids, Handoff: g.handoff})
	if err != nil {
		return err
	}
	_, err = g.savePrivateJSON("lifecycle-retired.json", raw)
	return err
}

// retire permanently fences an exact applying operation before releasing its
// reservation. There is no expiry or pruning. Older broker binaries do not
// enforce this journal: downgrade/rollback must preserve an enforcing broker.
func (g *lifecycleGate) retire(id string) Response {
	g.mu.Lock()
	defer g.mu.Unlock()
	admission, err := recoveryAdmission(g.directory)
	if err != nil {
		return Response{Code: "recovery_fenced"}
	}
	defer admission()
	if !jobID.MatchString(id) {
		return Response{Code: "invalid_operation_id"}
	}
	if g.retired[id] && (g.current.ID != id || g.current.Phase == "released") {
		return Response{State: "released"}
	}
	if g.current.ID != id || g.current.Phase != "applying" || (g.handoff != nil && g.handoff.OldID == id) {
		return Response{Code: "lifecycle_not_owned"}
	}
	// Fence in memory even on persistence failure: a rename or directory sync
	// failure has an uncertain disk outcome and must never reopen attachment.
	g.retired[id] = true
	if err := g.saveRetired(); err != nil {
		return Response{Code: "lifecycle_persistence_failed"}
	}
	// Drop our own OFD, then prove all external holders have also closed. A
	// surviving old operator keeps the durable applying gate closed until retry.
	if g.lock != nil {
		_ = g.lock.Close()
		g.lock = nil
	}
	lock, err := controllerLock(filepath.Join(g.directory, "infrastructure.lock"))
	if err != nil {
		return Response{Code: "infrastructure_busy"}
	}
	g.lock = lock
	previous := g.current
	if err := g.save(lifecycleState{ID: id, Phase: "released"}); err != nil {
		g.current = previous
		return Response{Code: "lifecycle_persistence_failed"}
	}
	_ = g.lock.Close()
	g.lock = nil
	return Response{State: "released"}
}

func (g *lifecycleGate) transition(id, phase string) Response {
	return g.transitionWithLock(id, phase, nil)
}
func (g *lifecycleGate) transitionWithLock(id, phase string, existing *os.File, resume ...bool) Response {
	g.mu.Lock()
	defer g.mu.Unlock()
	admission, err := recoveryAdmission(g.directory)
	if err != nil {
		return Response{Code: "recovery_fenced"}
	}
	defer admission()
	if !jobID.MatchString(id) {
		return Response{Code: "invalid_operation_id"}
	}
	if g.retired[id] {
		return Response{Code: "lifecycle_retired"}
	}
	active := g.current.Phase == "applying" || g.current.Phase == "checking"
	if len(resume) > 0 && resume[0] && (!active || g.current.ID != id) {
		return Response{Code: "lifecycle_not_owned"}
	}
	if active && g.current.ID != id {
		return Response{Code: "lifecycle_busy"}
	}
	if phase == "released" && g.current.ID != id {
		return Response{Code: "lifecycle_not_owned"}
	}
	if phase == "checking" && !active {
		return Response{Code: "lifecycle_not_owned"}
	}
	if g.current.ID == id && g.current.Phase == phase && (phase != "applying" || g.lock != nil) {
		return Response{State: phase}
	}
	var acquired *os.File
	if phase == "applying" && g.lock == nil {
		var err error
		if existing != nil {
			acquired, err = retainInfrastructureLock(existing, filepath.Join(g.directory, "infrastructure.lock"))
		} else {
			acquired, err = controllerLock(filepath.Join(g.directory, "infrastructure.lock"))
		}
		if err != nil {
			return Response{Code: "infrastructure_busy"}
		}
	}
	if err := g.save(lifecycleState{ID: id, Phase: phase}); err != nil {
		if acquired != nil {
			if g.current.ID == id && g.current.Phase == phase {
				g.lock = acquired
			} else {
				_ = acquired.Close()
			}
		}
		return Response{Code: "lifecycle_persistence_failed"}
	}
	if acquired != nil {
		g.lock = acquired
	}
	if phase != "applying" && g.lock != nil {
		_ = g.lock.Close()
		g.lock = nil
	}
	return Response{State: phase}
}
func (g *lifecycleGate) jobLock(operation string) (*os.File, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	admission, err := recoveryAdmission(g.directory)
	if err != nil {
		return nil, err
	}
	defer admission()
	if g.current.Phase == "applying" || (g.current.Phase == "checking" && operation == "configure-exit") {
		return nil, errors.New("lifecycle busy")
	}
	return controllerLock(filepath.Join(g.directory, "infrastructure.lock"))
}

// attach returns the same locked open-file-description after the operator dies.
// A different operation can never acquire it by guessing a new lease identifier.
func (g *lifecycleGate) attach(id string) Response {
	g.mu.Lock()
	defer g.mu.Unlock()
	admission, err := recoveryAdmission(g.directory)
	if err != nil {
		return Response{Code: "recovery_fenced"}
	}
	defer admission()
	if g.retired[id] {
		return Response{Code: "lifecycle_retired"}
	}
	if !jobID.MatchString(id) || g.current.ID != id || (g.current.Phase != "applying" && g.current.Phase != "checking") {
		return Response{Code: "lifecycle_not_owned"}
	}
	if g.lock == nil {
		lock, err := controllerLock(filepath.Join(g.directory, "infrastructure.lock"))
		if err != nil {
			return Response{Code: "infrastructure_busy"}
		}
		g.lock = lock
	}
	if g.current.Phase != "applying" {
		if err := g.save(lifecycleState{ID: id, Phase: "applying"}); err != nil {
			return Response{Code: "lifecycle_persistence_failed"}
		}
	}
	duplicate, err := retainInfrastructureLock(g.lock, filepath.Join(g.directory, "infrastructure.lock"))
	if err != nil {
		return Response{Code: "lifecycle_attachment_failed"}
	}
	return Response{State: "applying", leaseOutputs: []*os.File{duplicate}}
}

// WithLifecycleOperationLock resumes a bridge-local lease retained by the
// broker. The operator must separately serialize its immutable attempt journal.
func (c Client) WithLifecycleOperationLock(ctx context.Context, directory, id string) (context.Context, func(), error) {
	if !jobID.MatchString(id) {
		return ctx, nil, errors.New("invalid operation id")
	}
	leased, release, err := WithOperationLock(ctx, directory)
	if err == nil {
		return leased, release, nil
	}
	if !controllerLockBusy(err) {
		return ctx, nil, err
	}
	return c.WithActiveLifecycleOperationLock(ctx, directory, id)
}

// WithActiveLifecycleOperationLock requires the broker to authorize the exact
// active lifecycle, even when the local flock is free. Frozen-stage retries use
// this path so a released or retired attempt cannot replay infrastructure work.
func (c Client) WithActiveLifecycleOperationLock(ctx context.Context, directory, id string) (context.Context, func(), error) {
	if !jobID.MatchString(id) {
		return ctx, nil, errors.New("invalid operation id")
	}
	response, err := c.exchange(ctx, Message{Action: "lease-attach", ID: id})
	if err != nil {
		return ctx, nil, err
	}
	defer closeInputs(response.leaseOutputs)
	if response.State != "applying" || len(response.leaseOutputs) != 1 {
		return ctx, nil, errors.New("invalid lifecycle attachment state")
	}
	file, err := retainInfrastructureLock(response.leaseOutputs[0], filepath.Join(directory, "infrastructure.lock"))
	if err != nil {
		return ctx, nil, errors.New("untrusted lifecycle descriptor")
	}
	lease := &operationLease{directory: directory, file: file}
	lease.active.Store(true)
	return context.WithValue(ctx, operationLeaseKey{}, lease), func() {
		lease.run.Lock()
		defer lease.run.Unlock()
		if lease.active.Swap(false) {
			_ = file.Close()
		}
	}, nil
}

// Lifecycle changes require a root peer; relay is only allowed to inspect readiness.
func (c Client) Lifecycle(ctx context.Context, id, phase string) error {
	actions := map[string]string{"applying": "lease-applying", "checking": "lease-checking", "released": "lease-release"}
	action, ok := actions[phase]
	if !ok {
		return errors.New("invalid lifecycle phase")
	}
	_, err := c.exchange(ctx, Message{Action: action, ID: id})
	return err
}

func (g *lifecycleGate) phase() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	admission, err := recoveryAdmission(g.directory)
	if err != nil {
		return "recovery_fenced"
	}
	defer admission()
	if g.current.Phase == "" {
		return "released"
	}
	return g.current.Phase
}
func (c Client) TopologyFrozen(ctx context.Context) (bool, error) {
	r, err := c.exchange(ctx, Message{Action: "lifecycle-status"})
	if err != nil {
		return false, err
	}
	switch r.State {
	case "applying", "checking", "recovery_fenced":
		return true, nil
	case "released":
		return false, nil
	default:
		return false, errors.New("invalid lifecycle state")
	}
}

// LifecycleWithOperationLock transfers a duplicate of the existing bridge-local
// flock to the root broker. Its open-file-description survives client closure.
func (c Client) LifecycleWithOperationLock(ctx context.Context, id, phase string) error {
	if phase != "applying" {
		return c.Lifecycle(ctx, id, phase)
	}
	lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease)
	if !ok {
		return c.Lifecycle(ctx, id, phase)
	}
	lease.run.Lock()
	defer lease.run.Unlock()
	if !lease.active.Load() {
		return errors.New("operation lease inactive")
	}
	_, err := c.exchange(ctx, Message{Action: "lease-applying", ID: id, leaseInputs: []*os.File{lease.file}})
	return err
}

func (c Client) ResumeLifecycleWithOperationLock(ctx context.Context, id string) error {
	message := Message{Action: "lease-resume", ID: id}
	if lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease); ok {
		lease.run.Lock()
		defer lease.run.Unlock()
		if !lease.active.Load() {
			return errors.New("operation lease inactive")
		}
		message.leaseInputs = []*os.File{lease.file}
	}
	_, err := c.exchange(ctx, message)
	return err
}

// RetireLifecycle permanently fences an exact applying UUID. It requires a root
// peer and may need retry after an old operator closes its infrastructure lock.
func (c Client) RetireLifecycle(ctx context.Context, id string) error {
	response, err := c.exchange(ctx, Message{Action: "lease-retire", ID: id})
	if err != nil {
		return err
	}
	if response.State != "released" {
		return errors.New("invalid lifecycle retirement state")
	}
	return nil
}

// supersede preserves the verified locked OFD throughout the handoff. The
// retirement ledger is also its write-ahead intent, reconciled on broker start.
func (g *lifecycleGate) supersede(oldID, newID string, existing *os.File) Response {
	g.mu.Lock()
	defer g.mu.Unlock()
	admission, err := recoveryAdmission(g.directory)
	if err != nil {
		return Response{Code: "recovery_fenced"}
	}
	defer admission()
	if !jobID.MatchString(oldID) || !jobID.MatchString(newID) || oldID == newID {
		return Response{Code: "invalid_operation_id"}
	}
	same := g.handoff != nil && g.handoff.OldID == oldID && g.handoff.NewID == newID
	if g.current.Phase != "applying" || (g.current.ID != oldID && (!same || g.current.ID != newID)) {
		return Response{Code: "lifecycle_not_owned"}
	}
	if g.retired[newID] || (g.retired[oldID] && !same) {
		return Response{Code: "lifecycle_retired"}
	}
	if existing == nil {
		return Response{Code: "lifecycle_attachment_failed"}
	}
	retained, err := retainInfrastructureLock(existing, filepath.Join(g.directory, "infrastructure.lock"))
	if err != nil {
		return Response{Code: "lifecycle_attachment_failed"}
	}
	if g.lock == nil {
		g.lock = retained
	} else {
		_ = retained.Close()
	}
	g.retired[oldID] = true
	g.handoff = &lifecycleHandoff{OldID: oldID, NewID: newID}
	if err := g.saveRetired(); err != nil {
		return Response{Code: "lifecycle_persistence_failed"}
	}
	if err := g.save(lifecycleState{ID: newID, Phase: "applying"}); err != nil {
		return Response{Code: "lifecycle_persistence_failed"}
	}
	return Response{State: "applying"}
}

// SupersedeLifecycle atomically retires oldID and reserves newID under the
// caller's existing operation lease. Only a root peer may perform the handoff.
func (c Client) SupersedeLifecycle(ctx context.Context, oldID, newID string) error {
	lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease)
	if !ok {
		return errors.New("operation lease required")
	}
	lease.run.Lock()
	defer lease.run.Unlock()
	if !lease.active.Load() {
		return errors.New("operation lease inactive")
	}
	_, err := c.exchange(ctx, Message{Action: "lease-supersede", ID: oldID, NextID: newID, leaseInputs: []*os.File{lease.file}})
	return err
}
