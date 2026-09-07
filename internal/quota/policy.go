// Package quota allocates a daily allowance from a shared monthly exit budget.
package quota

import "math"

const GiB int64 = 1 << 30

type Demand struct {
	ID            string
	Today, Recent int64
}

// Allocate uses recent demand, not the number of registered accounts. Idle accounts
// get only a starter allowance, without reserving it from the shared pool.
func Allocate(pool int64, users []Demand) map[string]int64 {
	out := map[string]int64{}
	var weights float64
	for _, u := range users {
		if u.Recent > 0 {
			weights += math.Sqrt(float64(u.Recent))
		}
	}
	starter := min(pool, 2*GiB)
	for _, u := range users {
		limit := starter
		if u.Recent > 0 && weights > 0 {
			limit = max(starter, int64(float64(pool)*math.Sqrt(float64(u.Recent))/weights))
		}
		out[u.ID] = max(0, min(pool, limit))
	}
	return out
}
