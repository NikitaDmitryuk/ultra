package auth

import (
	"errors"
	"reflect"
	"sync"
)

var ErrRouteApply = errors.New("route application pending")

// RouteApplications records only confirmed server routes. Access credentials stay internal.
// Begin/Finish are called by the relay's single serialized application path.
type routeIntent struct{ Exit, Preferred string }

type RouteApplications struct {
	mu                        sync.RWMutex
	desired, applied          map[string]routeIntent
	revision, appliedRevision uint64
	applying                  bool
	failed                    bool
}
type RouteApplication struct {
	State           string `json:"state"`
	Revision        uint64 `json:"revision"`
	AppliedRevision uint64 `json:"applied_revision"`
	EffectiveExit   string `json:"effective_exit_id"`
	Error           string `json:"error,omitempty"`
}

func (r *RouteApplications) Begin(users []User) {
	next := make(map[string]routeIntent, len(users))
	for _, u := range users {
		intent := routeIntent{Exit: u.EffectiveExitID}
		if u.PreferredExitID != nil {
			intent.Preferred = *u.PreferredExitID
		}
		next[u.UUID] = intent
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if !reflect.DeepEqual(next, r.desired) {
		r.revision++
		r.desired = next
	}
	r.applying = true
}
func (r *RouteApplications) Finish(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.applying = false
	r.failed = err != nil
	if err == nil {
		r.applied = r.desired
		r.appliedRevision = r.revision
	}
}
func (r *RouteApplications) Pending() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.failed || r.appliedRevision != r.revision
}
func (r *RouteApplications) Status(id string) RouteApplication {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s := RouteApplication{State: "applied", Revision: r.revision, AppliedRevision: r.appliedRevision, EffectiveExit: r.applied[id].Exit}
	if _, ok := r.applied[id]; !ok || r.applying || r.revision != r.appliedRevision {
		s.State = "applying"
	}
	if r.failed {
		s.State = "error"
		s.Error = "route_apply_failed"
	}
	return s
}
