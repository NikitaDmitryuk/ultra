// Package quota computes monthly ceilings without reserving idle users' shares.
package quota

const GiB int64 = 1 << 30

func PersonalLimit(monthly int64) int64 { return max(0, monthly-monthly/5) / 4 }

// Available is bounded by both the shared safe remainder and the owner's ceiling.
func Available(monthly, used, shared int64, fallback bool) int64 {
	if fallback {
		return max(0, shared)
	}
	return max(0, min(shared, PersonalLimit(monthly)-used))
}
