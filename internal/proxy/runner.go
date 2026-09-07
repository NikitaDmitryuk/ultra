package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
)

// Runner owns a single in-process xray core.Instance and supports reload.
type Runner struct {
	mu sync.Mutex

	inst   *core.Instance
	config *core.Config
	status ReloadStatus
}

// ReloadStatus exposes lifecycle events without configuration or credentials.
type ReloadStatus struct {
	Count  uint64    `json:"count"`
	At     time.Time `json:"at,omitempty"`
	Reason string    `json:"reason,omitempty"`
	Error  string    `json:"error,omitempty"`
}

func (r *Runner) Status() ReloadStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

func (r *Runner) StartJSON(data []byte) error { return r.ReloadReason(data, "configuration") }
func (r *Runner) Reload(data []byte) error    { return r.ReloadReason(data, "configuration") }

// ReloadReason validates before closing listeners and restores the last valid config on failure.
func (r *Runner) ReloadReason(data []byte, reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var input any
	if err := json.Unmarshal(data, &input); err != nil {
		return fmt.Errorf("parse configuration: %w", err)
	}
	canonical, err := json.Marshal(input)
	if err != nil {
		return err
	}
	cfg, err := core.LoadConfig("json", bytes.NewReader(canonical))
	if err != nil {
		return fmt.Errorf("build configuration: %w", err)
	}
	if r.inst != nil && proto.Equal(cfg, r.config) {
		r.status.Error = ""
		return nil
	}
	next, err := core.New(cfg)
	if err != nil {
		return fmt.Errorf("prepare configuration: %w", err)
	}
	old := r.config
	if r.inst != nil {
		_ = r.inst.Close()
		r.inst = nil
	}
	r.status = ReloadStatus{Count: r.status.Count + 1, At: time.Now().UTC(), Reason: reason}
	if err = next.Start(); err != nil {
		_ = next.Close()
		r.status.Error = "start failed"
		if old != nil {
			restored, restoreErr := core.New(old)
			if restoreErr == nil {
				restoreErr = restored.Start()
			}
			if restoreErr != nil {
				if restored != nil {
					_ = restored.Close()
				}
				r.status.Error = "start and restore failed"
				return fmt.Errorf("start: %w; restore: %v", err, restoreErr)
			}
			r.inst = restored
		}
		return fmt.Errorf("start failed (previous configuration restored if available): %w", err)
	}
	r.inst = next
	r.config = cfg
	return nil
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
