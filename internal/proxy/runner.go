package proxy

import (
	"context"
	"sync"

	"github.com/NikitaDmitryuk/ultra/internal/trace"
	xraylog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
)

// Runner owns a single in-process xray core.Instance and supports reload.
type Runner struct {
	mu sync.Mutex

	inst       *core.Instance
	traceStore *trace.Store // nil when tracing is disabled
}

// SetTraceStore configures a trace store whose LogHandler will be registered
// as xray's global log handler after every (re)start.
// Must be called before the first StartJSON / Reload.
func (r *Runner) SetTraceStore(s *trace.Store) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.traceStore = s
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
	// Register the trace log handler AFTER xray has set up its own handler so
	// ours replaces it. Our handler tees all messages back to stderr, so no
	// log output is lost.
	if r.traceStore != nil {
		xraylog.RegisterHandler(trace.NewLogHandler(r.traceStore))
	}
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
