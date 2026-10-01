package auth

import (
	"slices"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

// BlockedExit is an internal sentinel, never a physical exit ID.
const BlockedExit = "_quota_block"

func (u User) SelectExit(nodes []exits.Node, active string, health map[string]exits.Health) string {
	allowed := make([]exits.Node, 0, len(nodes))
	eligible := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		if !n.Enabled || slices.Contains(u.ExcludedExitIDs, n.ID) {
			continue
		}
		if u.FixedExit {
			// A location credential never falls back, including while its exit is down.
			if u.PreferredExitID != nil && n.ID == *u.PreferredExitID {
				return n.ID
			}
			continue
		}
		allowed = append(allowed, n)
		h, known := health[n.ID]
		eligible[n.ID] = !known || h.Eligible
		// The selector already applies the failback stability window to active.
		if n.ID == active && eligible[n.ID] {
			return n.ID
		}
	}
	if !u.FixedExit {
		if candidate, ok := exits.SelectActive(allowed, eligible); ok {
			return candidate.ID
		}
	}
	return BlockedExit
}
