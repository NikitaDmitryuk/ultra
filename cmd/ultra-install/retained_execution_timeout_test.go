package main

import "testing"

func TestRetainedExecutionTimeoutBinding(t *testing.T) {
	valid, invalid := int64(3600), int64(0)
	if !retainedExecutionTimeoutMatches(0, nil) || !retainedExecutionTimeoutMatches(valid, &valid) {
		t.Fatal("valid legacy/new request rejected")
	}
	if retainedExecutionTimeoutMatches(valid, nil) || retainedExecutionTimeoutMatches(0, &valid) ||
		retainedExecutionTimeoutMatches(valid, &invalid) || retainedExecutionTimeoutMatches(0, &invalid) {
		t.Fatal("changed or unbound budget accepted")
	}
}
