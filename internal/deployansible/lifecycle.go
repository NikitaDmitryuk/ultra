package deployansible

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
}
type lifecycleState struct {
	ID    string `json:"id"`
	Phase string `json:"phase"`
}

func openLifecycleGate(directory string) (*lifecycleGate, error) {
	g := &lifecycleGate{directory: directory}
	path := filepath.Join(directory, "lifecycle.json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return g, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !ownedByProcess(info) {
		return nil, errors.New("invalid lifecycle journal")
	}
	raw, err := os.ReadFile(path)
	if err != nil || json.Unmarshal(raw, &g.current) != nil || !jobID.MatchString(g.current.ID) || (g.current.Phase != "applying" && g.current.Phase != "checking" && g.current.Phase != "released") {
		return nil, errors.New("invalid lifecycle journal")
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
	return g.current.Phase == "applying" || g.current.Phase == "checking"
}
func (g *lifecycleGate) save(next lifecycleState) error {
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(g.directory, ".lifecycle-")
	if err != nil {
		return err
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
		return err
	}
	if err = os.Rename(name, filepath.Join(g.directory, "lifecycle.json")); err != nil {
		return err
	}
	g.current = next
	if err = syncDirectory(g.directory); err != nil {
		return err
	}
	return nil
}
func (g *lifecycleGate) transition(id, phase string) Response {
	return g.transitionWithLock(id, phase, nil)
}
func (g *lifecycleGate) transitionWithLock(id, phase string, existing *os.File, resume ...bool) Response {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !jobID.MatchString(id) {
		return Response{Code: "invalid_operation_id"}
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
	response, err := c.exchange(ctx, Message{Action: "lease-attach", ID: id})
	if err != nil {
		return ctx, nil, err
	}
	defer closeInputs(response.leaseOutputs)
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
	case "applying", "checking":
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
