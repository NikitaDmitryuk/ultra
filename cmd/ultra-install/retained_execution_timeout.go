package main

// Legacy prepared requests omit both fields. A new request must preserve the
// exact positive budget authenticated by the retained recovery binding.
func retainedExecutionTimeoutMatches(prepared int64, submitted *int64) bool {
	if submitted == nil {
		return prepared == 0
	}
	return prepared > 0 && prepared <= 9223371976 && *submitted == prepared
}
