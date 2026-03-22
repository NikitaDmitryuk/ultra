package proxy

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/core"
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
