package main

import (
	"slices"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

// A bounded read-only view of existing diagnostics. Unknown/stale probes cannot
// establish complete loss of VPN; a quota exclusion is a separate cause.
func (r *bridgeRuntime) personalRouteSnapshot() []db.PersonalRouteObservation {
	r.applyMu.Lock()
	defer r.applyMu.Unlock()
	r.mu.RLock()
	defer r.mu.RUnlock()
	health := r.selector.HealthSnapshot()
	now := r.now()
	out := make([]db.PersonalRouteObservation, 0, len(r.users))
	for _, u := range r.users {
		v := db.PersonalRouteObservation{
			Account: u.AccountID,
			Known:   !r.fault && !r.confirmed.IsZero() && now.Before(r.confirmed.Add(runtimeLease)) && r.runner.Status().Error == "",
		}
		runtimeKnown := v.Known
		candidates, quotaBlocked := 0, 0
		for _, n := range r.nodes {
			if !n.Enabled {
				continue
			}
			candidates++
			left, e := r.state.Remaining(u.AccountID, n.ID)
			if e != nil {
				v.Known = false
				continue
			}
			if slices.Contains(u.ExcludedExitIDs, n.ID) {
				switch u.ExitExclusionReasons[n.ID] {
				case "exit_budget_exhausted", "monthly_user_limit_exhausted", "provider_emergency_exhausted", "monitor_quota_exhausted":
				default:
					v.Known = false
					continue
				}
			}
			if slices.Contains(u.ExcludedExitIDs, n.ID) || left <= 0 {
				quotaBlocked++
				continue
			}
			h, ok := health[n.ID]
			if !ok || h.CheckedAt.IsZero() || now.Sub(h.CheckedAt) > 30*time.Second || now.Before(h.CheckedAt) {
				v.Known = false
				continue
			}
			if h.Eligible && h.InternetOK {
				v.Available = true
			}
		}
		if v.Available {
			v.Known = runtimeKnown
		}
		if candidates == 0 {
			v.Known = false
		}
		v.QuotaBlocked = candidates > 0 && quotaBlocked == candidates
		out = append(out, v)
	}
	return out
}
