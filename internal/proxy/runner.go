package proxy

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
)

// Runner owns a single in-process xray core.Instance and supports reload.
type Runner struct {
	mu sync.Mutex

	inst *core.Instance
}

// StartJSON parses JSON, starts xray (caller must import distro/all in main).
func (r *Runner) StartJSON(jsonCfg []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inst != nil {
		_ = r.inst.Close()
		r.inst = nil
	}
	inst, err := core.StartInstance("json", jsonCfg)
	if err != nil {
		return err
	}
	r.inst = inst
	return nil
}

// Reload replaces the running instance with a new config.
func (r *Runner) Reload(jsonCfg []byte) error {
	return r.StartJSON(jsonCfg)
}

// Close stops xray.
func (r *Runner) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inst == nil {
		return nil
	}
	err := r.inst.Close()
	r.inst = nil
	return err
}

// Shutdown is Close with context (for symmetry; xray closes synchronously).
func (r *Runner) Shutdown(_ context.Context) error {
	return r.Close()
}

// Instance returns the running xray core.Instance, or nil if not started.
// The caller must not close the instance directly.
func (r *Runner) Instance() *core.Instance {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.inst
}

// GetStatsManager returns the Xray stats.Manager feature of the running instance,
// or nil when the instance is stopped or stats are not enabled in the config.
func (r *Runner) GetStatsManager() stats.Manager {
	r.mu.Lock()
	inst := r.inst
	r.mu.Unlock()
	if inst == nil {
		return nil
	}
	f := inst.GetFeature(stats.ManagerType())
	if f == nil {
		return nil
	}
	sm, _ := f.(stats.Manager)
	return sm
}

// PeekCounter returns the current value of a named stats counter without resetting it.
func (r *Runner) PeekCounter(name string) int64 {
	sm := r.GetStatsManager()
	if sm == nil {
		return 0
	}
	c := sm.GetCounter(name)
	if c == nil {
		return 0
	}
	if v, ok := c.(interface{ Value() int64 }); ok {
		return v.Value()
	}
	if a, ok := c.(interface{ Add(int64) int64 }); ok {
		return a.Add(0)
	}
	return 0
}
