package auth

import (
	"slices"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

// BlockedExit is an internal sentinel, never a physical exit ID.
const BlockedExit = "_quota_block"

func (u User) SelectExit(nodes []exits.Node, active string, health map[string]exits.Health) string {
	// A deleted credential is not converted into another active credential. An
	// existing location is a preference and may use another allowed healthy exit.
	if u.FixedExit {
		exists := false
		for _, n := range nodes {
			if u.PreferredExitID != nil && n.ID == *u.PreferredExitID {
				exists = true
				break
			}
		}
		if !exists {
			return BlockedExit
		}
	}
	allowed := make([]exits.Node, 0, len(nodes))
	eligible := make(map[string]bool, len(nodes))
	for _, n := range nodes {
		if !n.Enabled || slices.Contains(u.ExcludedExitIDs, n.ID) {
			continue
		}
		allowed = append(allowed, n)
		h, known := health[n.ID]
		eligible[n.ID] = !known || h.Eligible
		if u.FixedExit && u.PreferredExitID != nil && n.ID == *u.PreferredExitID && eligible[n.ID] && (!known || h.PreferredReady) {
			return n.ID
		}
	}
	for _, n := range allowed {
		if n.ID == active && eligible[n.ID] {
			return n.ID
		}
	}
	if candidate, ok := exits.SelectActive(allowed, eligible); ok {
		return candidate.ID
	}
	return BlockedExit
}
