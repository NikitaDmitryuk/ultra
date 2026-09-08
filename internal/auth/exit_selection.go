package auth

import (
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"slices"
)

// BlockedExit is an internal sentinel, never a physical exit ID.
const BlockedExit = "_quota_block"

func (u User) SelectExit(nodes []exits.Node, active string, health map[string]exits.Health) string {
	selected := active
	if u.PreferredExitID != nil {
		for _, n := range nodes {
			if n.ID == *u.PreferredExitID {
				if h, ok := health[n.ID]; !ok || h.PreferredReady {
					selected = n.ID
				}
				break
			}
		}
	}
	if !slices.Contains(u.ExcludedExitIDs, selected) {
		return selected
	}
	for _, n := range nodes {
		if n.ID == u.FallbackExitID && !slices.Contains(u.ExcludedExitIDs, n.ID) {
			if h, ok := health[n.ID]; !ok || h.Eligible {
				return n.ID
			}
		}
	}
	return BlockedExit
}
