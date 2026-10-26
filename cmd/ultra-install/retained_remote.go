package main

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"

	"github.com/NikitaDmitryuk/ultra/internal/operatorssh"
)

// A lost mutation response never authorizes replay, even for a guarded SQL transaction.
func runRetainedMutationSSH(ctx context.Context, role string, args []string, stdin []byte, log func(string)) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	start := time.Now()
	policy := operatorssh.DefaultPolicy
	result := replacementSSHRunner().Run(ctx, args, stdin, policy.MaxStdoutBytes, policy.MaxStderrBytes)
	kind := operatorssh.Classify(result)
	if ctx.Err() != nil {
		kind = "cancelled"
	} else if result.StdoutTruncated {
		kind = "output_invalid"
	} else if result.Err == nil && result.ExitCode == 0 {
		kind = "ok"
	}
	reason := operatorssh.DiagnosticReason(result)
	if log != nil {
		log(
			fmt.Sprintf(
				"remote role=%s attempt=1/1 rc=%d kind=%s reason=%s elapsed=%s",
				role,
				result.ExitCode,
				retainedLogKind(kind),
				retainedLogReason(reason),
				time.Since(start).Round(time.Millisecond),
			),
		)
	}
	if kind == "ok" {
		return result.Stdout, nil
	}
	if kind == "transient_transport" {
		kind = "transport_exhausted"
	}
	return nil, &operatorssh.Error{Kind: kind, Reason: reason, Attempts: 1, ExitCode: result.ExitCode}
}

// runRetainedReadOnlySSH is the adapter for retainedRemote's non-mutating reads.
// Mutation paths must continue using direct SSH execution without retries.
func runRetainedReadOnlySSH(ctx context.Context, role string, args []string, stdin []byte, log func(string)) ([]byte, error) {
	executor := operatorssh.Executor{Policy: operatorssh.DefaultPolicy, Runner: replacementSSHRunner()}
	if log != nil {
		executor.Log = func(role string, attempt, max, rc int, kind, reason string, elapsed time.Duration) {
			log(
				"remote role=" + role + " attempt=" + strconv.Itoa(
					attempt,
				) + "/" + strconv.Itoa(
					max,
				) + " rc=" + strconv.Itoa(
					rc,
				) + " kind=" + retainedLogKind(
					kind,
				) + " reason=" + retainedLogReason(reason) + " elapsed=" + elapsed.Round(time.Millisecond).
					String(),
			)
		}
	}
	return executor.ReadOnly(ctx, role, args, stdin)
}

// retainedReadOnlyFailureKind lets callers preserve the distinction between
// exhausted transport and a remote command failure without exposing diagnostics.
func retainedReadOnlyFailureKind(err error) string {
	var remoteErr *operatorssh.Error
	if errors.As(err, &remoteErr) {
		return remoteErr.Kind
	}
	return "program_failure"
}

func retainedLogKind(kind string) string {
	switch kind {
	case "ok":
		return "success"
	case "transient_transport", "transport_exhausted":
		return "transport"
	case "permanent":
		return "permanent"
	case "cancelled":
		return "cancelled"
	default:
		return "program"
	}
}

func retainedLogReason(reason string) string {
	switch reason {
	case "timeout", "reset", "closed", "refused", "no_route", "broken_pipe", "auth", "host_key", "unknown":
		return reason
	default:
		return "unknown"
	}
}

func replacementSSHRunner() operatorssh.ExecRunner {
	return operatorssh.ExecRunner{Prepare: func(ctx context.Context, command *exec.Cmd) error {
		return deployansible.RetainReplacementSSH(ctx, command)
	}}
}
