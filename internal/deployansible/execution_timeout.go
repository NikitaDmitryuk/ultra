package deployansible

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"
)

type executionTimeoutKey struct{}
type operationExecutionTimeoutKey string

// WithOperationExecutionTimeout changes only the named operation's execution
// budget. Ancillary operations keep their historical defaults.
func WithOperationExecutionTimeout(ctx context.Context, operation string, timeout time.Duration) (context.Context, error) {
	validated, err := WithExecutionTimeout(ctx, timeout)
	if err != nil || operation == "" {
		return ctx, errors.New("invalid_execution_timeout")
	}
	return context.WithValue(ctx, operationExecutionTimeoutKey(operation), validated.Value(executionTimeoutKey{})), nil
}

// WithExecutionTimeout fixes the execution budget in subsequently prepared job
// requests. It does not change readiness budgets or grant retry authorization.
func WithExecutionTimeout(ctx context.Context, timeout time.Duration) (context.Context, error) {
	if timeout <= 0 || timeout%time.Second != 0 || timeout > time.Duration(1<<63-1)-time.Minute {
		return ctx, errors.New("invalid_execution_timeout")
	}
	return context.WithValue(ctx, executionTimeoutKey{}, int64(timeout/time.Second)), nil
}

func executionTimeoutSeconds(ctx context.Context, operation string) int64 {
	if operation == "wait-upgrade-readiness" {
		return 700
	}
	if seconds, ok := ctx.Value(operationExecutionTimeoutKey(operation)).(int64); ok {
		return seconds
	}
	if seconds, ok := ctx.Value(executionTimeoutKey{}).(int64); ok {
		return seconds
	}
	if operation == "upgrade" {
		return 3600
	}
	return 1200
}

func explicitExecutionTimeout(ctx context.Context, operation string) bool {
	if operation == "wait-upgrade-readiness" {
		return false
	}
	_, scoped := ctx.Value(operationExecutionTimeoutKey(operation)).(int64)
	_, all := ctx.Value(executionTimeoutKey{}).(int64)
	return scoped || all
}

// Preserve admitted budgets without an override. Explicitly changing a frozen
// budget changes the request and remains subject to immutable admission checks.
func localExecutionRequest(ctx context.Context, operation, directory string, inventory, variables map[string]any) ([]byte, error) {
	seconds := executionTimeoutSeconds(ctx, operation)
	request := map[string]any{"inventory": inventory, "variables": variables, "execution_timeout_seconds": seconds}
	prior, priorErr := readRetryPrivate(filepath.Join(directory, "request.json"))
	var frozenSeconds *int64
	if priorErr == nil {
		var err error
		frozenSeconds, err = frozenExecutionTimeout(prior)
		if err != nil {
			return nil, err
		}
	}
	if priorErr == nil && !explicitExecutionTimeout(ctx, operation) && operation != "wait-upgrade-readiness" {
		if frozenSeconds != nil {
			candidate, err := json.Marshal(
				map[string]any{"inventory": inventory, "variables": variables, "execution_timeout_seconds": *frozenSeconds},
			)
			if err != nil {
				return nil, err
			}
			if bytes.Equal(prior, candidate) {
				return prior, nil
			}
		}
	}
	legacySeconds := int64(1200)
	if operation == "wait-upgrade-readiness" {
		legacySeconds = 700
	}
	if !explicitExecutionTimeout(ctx, operation) || seconds == legacySeconds {
		legacy, err := json.Marshal(map[string]any{"inventory": inventory, "variables": variables})
		if err != nil {
			return nil, err
		}
		if priorErr == nil && bytes.Equal(prior, legacy) {
			return prior, nil
		}
	}
	return json.Marshal(request)
}

func validExecutionTimeoutSeconds(seconds int64) bool {
	return seconds > 0 && seconds <= int64((time.Duration(1<<63-1)-time.Minute)/time.Second)
}

func frozenExecutionTimeout(raw []byte) (*int64, error) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, errors.New("invalid_frozen_execution_request")
	}
	canonical, err := json.Marshal(fields)
	if err != nil || !bytes.Equal(raw, canonical) || fields["inventory"] == nil || fields["variables"] == nil {
		return nil, errors.New("invalid_frozen_execution_request")
	}
	for key := range fields {
		if key != "inventory" && key != "variables" && key != "execution_timeout_seconds" {
			return nil, errors.New("invalid_frozen_execution_request")
		}
	}
	value, present := fields["execution_timeout_seconds"]
	if !present {
		return nil, nil
	}
	var budget int64
	if bytes.Equal(value, []byte("null")) || json.Unmarshal(value, &budget) != nil || !validExecutionTimeoutSeconds(budget) {
		return nil, errors.New("invalid_execution_timeout")
	}
	return &budget, nil
}

func frozenExitExecutionTimeout(raw []byte) (*int64, error) {
	var request ExitRequest
	if json.Unmarshal(raw, &request) != nil {
		return nil, errors.New("invalid_frozen_execution_request")
	}
	canonical, err := json.Marshal(request)
	if err != nil || !bytes.Equal(raw, canonical) {
		return nil, errors.New("invalid_frozen_execution_request")
	}
	if request.ExecutionTimeoutSeconds < 0 {
		return nil, errors.New("invalid_execution_timeout")
	}
	if request.ExecutionTimeoutSeconds == 0 {
		return nil, nil
	}
	if !validExecutionTimeoutSeconds(request.ExecutionTimeoutSeconds) {
		return nil, errors.New("invalid_execution_timeout")
	}
	return &request.ExecutionTimeoutSeconds, nil
}

// LocalRequestBytes reconstructs the exact request RunLocal will admit, including
// its context budget and legacy default replay. It never writes or dispatches.
func LocalRequestBytes(ctx context.Context, operation, directory string, inventory, variables map[string]any) ([]byte, error) {
	return localExecutionRequest(ctx, operation, directory, inventory, variables)
}

// A linked same-operation bootstrap generation replays the authenticated source
// request, including a legacy absent timeout. The exporter independently checks
// the source job hash and operation before these bytes can be prepared.
func pinnedLocalExecutionRequest(
	ctx context.Context,
	operation, directory, source string,
	inventory, variables map[string]any,
) ([]byte, error) {
	current, err := localExecutionRequest(ctx, operation, directory, inventory, variables)
	if err != nil {
		return nil, err
	}
	jobRaw, err := readRetryPrivate(filepath.Join(source, "job.json"))
	if err != nil {
		return nil, err
	}
	var job struct {
		Operation string `json:"operation"`
	}
	if json.Unmarshal(jobRaw, &job) != nil {
		return nil, errors.New("bootstrap_bundle_source_identity_invalid")
	}
	if job.Operation != operation {
		return current, nil
	}
	prior, err := localExecutionRequest(ctx, operation, source, inventory, variables)
	if err != nil {
		return nil, err
	}
	// The exporter requires byte equality with the source and authenticates it;
	// changed variables or an explicit changed budget therefore remain rejected.
	return prior, nil
}

func preparedExecutionTimeout(directory string) (time.Duration, error) {
	job, readErr := readRetryPrivate(filepath.Join(directory, "job.json"))
	var value struct {
		Operation string `json:"operation"`
	}
	if readErr != nil || json.Unmarshal(job, &value) != nil {
		return 0, errors.New("invalid_execution_timeout")
	}
	raw, err := readRetryPrivate(filepath.Join(directory, "request.json"))
	if err != nil {
		return 0, err
	}
	var budget *int64
	if value.Operation == "configure-exit" {
		budget, err = frozenExitExecutionTimeout(raw)
	} else {
		budget, err = frozenExecutionTimeout(raw)
	}
	if err != nil {
		return 0, err
	}
	if budget == nil {
		// Missing fields belong to legacy frozen requests. Fresh upgrades always
		// carry 3600 explicitly; never silently extend an old 1200s budget.
		if value.Operation == "wait-upgrade-readiness" {
			return 700 * time.Second, nil
		}
		return 1200 * time.Second, nil
	}
	seconds := *budget
	if !validExecutionTimeoutSeconds(seconds) {
		return 0, errors.New("invalid_execution_timeout")
	}
	return time.Duration(seconds) * time.Second, nil
}
