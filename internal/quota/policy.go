// Package quota computes monthly ceilings without reserving idle users' shares.
package quota

const GiB int64 = 1 << 30

// SafeBudget rounds the 80% ceiling down without overflowing multiplication.
func SafeBudget(monthly int64) int64 {
	monthly = max(0, monthly)
	return monthly/5*4 + monthly%5*4/5
}
func PersonalLimit(monthly int64) int64 { return SafeBudget(monthly) / 4 }

// Available is bounded by both the shared safe remainder and the owner's ceiling.
func Available(monthly, used, shared int64, fallback bool) int64 {
	if fallback {
		return max(0, shared)
	}
	return max(0, min(shared, PersonalLimit(monthly)-used))
}
