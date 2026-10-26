// Package operatorssh implements bounded, read-only operator SSH retries.
package operatorssh

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"time"

	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
)

// Policy mirrors deploy/recovery/ssh_policy.json; the test guards parity.
type Policy struct {
	Version                       int    `json:"version"`
	ProbeConnectTimeoutSeconds    int    `json:"probe_connect_timeout_seconds"`
	MutateConnectTimeoutSeconds   int    `json:"mutate_connect_timeout_seconds"`
	ServerAliveIntervalSeconds    int    `json:"server_alive_interval_seconds"`
	ServerAliveCountMax           int    `json:"server_alive_count_max"`
	StrictHostKeyChecking         string `json:"strict_host_key_checking"`
	UpdateHostKeys                string `json:"update_host_keys"`
	ReadonlyAttempts              int    `json:"readonly_attempts"`
	ReadonlyAttemptTimeoutSeconds int    `json:"readonly_attempt_timeout_seconds"`
	ReadonlyTotalTimeoutSeconds   int    `json:"readonly_total_timeout_seconds"`
	ReadonlyBackoffSeconds        []int  `json:"readonly_backoff_seconds"`
	MaxStdoutBytes                int    `json:"max_stdout_bytes"`
	MaxStderrBytes                int    `json:"max_stderr_bytes"`
}

// DefaultPolicy reads the same embedded artifact that the Python tools ship.
var DefaultPolicy = embeddedPolicy()

func embeddedPolicy() Policy {
	raw, err := recoveryassets.Scripts.ReadFile("ssh_policy.json")
	if err != nil {
		panic("embedded SSH policy missing")
	}
	var policy Policy
	if json.Unmarshal(raw, &policy) != nil || policy.Version != 1 {
		panic("embedded SSH policy invalid")
	}
	return policy
}

// Options returns OpenSSH -o arguments to insert before the destination in an argv.
// Use "probe" for read-only access and "mutate" for a mutation connection.
func (p Policy) Options(kind string) []string {
	timeout := p.ProbeConnectTimeoutSeconds
	if kind == "mutate" {
		timeout = p.MutateConnectTimeoutSeconds
	}
	return []string{
		"-o",
		"ConnectTimeout=" + strconv.Itoa(timeout),
		"-o",
		"ServerAliveInterval=" + strconv.Itoa(p.ServerAliveIntervalSeconds),
		"-o",
		"ServerAliveCountMax=" + strconv.Itoa(p.ServerAliveCountMax),
		"-o",
		"StrictHostKeyChecking=" + p.StrictHostKeyChecking,
		"-o",
		"UpdateHostKeys=" + p.UpdateHostKeys,
	}
}

type Result struct {
	Stdout, Stderr  []byte
	ExitCode        int
	Err             error
	StdoutTruncated bool
}
type Runner interface {
	Run(context.Context, []string, []byte, int, int) Result
}
type Sleep func(context.Context, time.Duration) error
type Log func(role string, attempt, max, rc int, kind, reason string, elapsed time.Duration)

type Executor struct {
	Policy Policy
	Runner Runner
	Sleep  Sleep
	Now    func() time.Time
	Log    Log
}
type Error struct {
	Kind     string
	Reason   string
	Attempts int
	ExitCode int
}

func (e *Error) Error() string {
	kind := safeErrorKind(e.Kind)
	reason := safeReason(e.Reason)
	if kind == "transport_exhausted" {
		return "SSH read-only transport retries exhausted (" + reason + ")"
	}
	return "SSH read-only remote command failed (" + kind + ", " + reason + ")"
}

func Classify(r Result) string {
	// A process deadline is independent evidence of a stalled transport. Child
	// command output and non-255 exit codes must never trigger an SSH retry.
	if errors.Is(r.Err, context.DeadlineExceeded) {
		return "transient_transport"
	}
	if r.ExitCode != 255 {
		return "program_failure"
	}
	s := strings.ToLower(string(r.Stderr))
	if strings.Contains(s, "permission denied") || strings.Contains(s, "host key verification failed") ||
		strings.Contains(s, "remote host identification has changed") {
		return "permanent"
	}
	for _, marker := range []string{"connection timed out", "operation timed out", "connection reset", "connection closed", "connection refused", "no route to host", "broken pipe"} {
		if strings.Contains(s, marker) {
			return "transient_transport"
		}
	}
	return "program_failure"
}

// DiagnosticReason returns a bounded, fixed reason suitable for errors and
// attempt logs. It never includes remote output or arbitrary process errors.
func DiagnosticReason(r Result) string {
	if errors.Is(r.Err, context.DeadlineExceeded) {
		return "timeout"
	}
	s := strings.ToLower(string(r.Stderr))
	if strings.Contains(s, "permission denied") {
		return "auth"
	}
	if strings.Contains(s, "host key verification failed") || strings.Contains(s, "remote host identification has changed") {
		return "host_key"
	}
	for _, marker := range []struct{ text, reason string }{
		{"connection timed out", "timeout"}, {"operation timed out", "timeout"},
		{"connection reset", "reset"}, {"connection closed", "closed"},
		{"connection refused", "refused"}, {"no route to host", "no_route"},
		{"broken pipe", "broken_pipe"},
	} {
		if strings.Contains(s, marker.text) {
			return marker.reason
		}
	}
	return "unknown"
}

func safeReason(reason string) string {
	switch reason {
	case "timeout", "reset", "closed", "refused", "no_route", "broken_pipe", "auth", "host_key", "unknown":
		return reason
	default:
		return "unknown"
	}
}

func safeErrorKind(kind string) string {
	switch kind {
	case "transport_exhausted", "cancelled", "permanent", "program_failure", "output_invalid":
		return kind
	default:
		return "program_failure"
	}
}

func (e Executor) ReadOnly(ctx context.Context, role string, args []string, stdin []byte) ([]byte, error) {
	role = safeRole(role)
	p := e.Policy
	if p.Version == 0 {
		p = DefaultPolicy
	}
	if e.Runner == nil {
		e.Runner = ExecRunner{}
	}
	if e.Now == nil {
		e.Now = time.Now
	}
	if e.Sleep == nil {
		e.Sleep = sleepContext
	}
	parentCtx := ctx
	ctx, cancel := context.WithTimeout(parentCtx, time.Duration(p.ReadonlyTotalTimeoutSeconds)*time.Second)
	defer cancel()
	start := e.Now()
	attempts := 0
	var last Result
	for n := 1; n <= p.ReadonlyAttempts; n++ {
		if err := ctx.Err(); err != nil {
			kind := "transport_exhausted"
			if parentCtx.Err() != nil {
				kind = "cancelled"
			}
			return nil, &Error{Kind: kind, Reason: DiagnosticReason(last), Attempts: n - 1, ExitCode: last.ExitCode}
		}
		attemptCtx, stop := context.WithTimeout(ctx, time.Duration(p.ReadonlyAttemptTimeoutSeconds)*time.Second)
		t0 := e.Now()
		last = e.Runner.Run(attemptCtx, args, stdin, p.MaxStdoutBytes, p.MaxStderrBytes)
		attemptErr := attemptCtx.Err()
		attempts = n
		stop()
		if attemptErr != nil {
			last.Err = attemptErr
		}
		kind := Classify(last)
		if parentCtx.Err() != nil {
			kind = "cancelled"
		} else if ctx.Err() != nil {
			kind = "transport_exhausted"
		}
		if last.Err == nil && last.ExitCode == 0 {
			if last.StdoutTruncated {
				if e.Log != nil {
					e.Log(role, n, p.ReadonlyAttempts, 0, "output_invalid", "unknown", e.Now().Sub(t0))
				}
				return nil, &Error{Kind: "output_invalid", Reason: "unknown", Attempts: attempts, ExitCode: 0}
			}
			if e.Log != nil {
				e.Log(role, n, p.ReadonlyAttempts, 0, "ok", "unknown", e.Now().Sub(t0))
			}
			return last.Stdout, nil
		}
		rc := last.ExitCode
		if rc == 0 {
			rc = 255
		}
		if e.Log != nil {
			e.Log(role, n, p.ReadonlyAttempts, rc, kind, DiagnosticReason(last), e.Now().Sub(t0))
		}
		if kind != "transient_transport" || len(last.Stdout) > 0 || last.StdoutTruncated || n == p.ReadonlyAttempts {
			break
		}
		if e.Now().Sub(start) >= time.Duration(p.ReadonlyTotalTimeoutSeconds)*time.Second {
			break
		}
		if n-1 < len(p.ReadonlyBackoffSeconds) {
			if err := e.Sleep(ctx, time.Duration(p.ReadonlyBackoffSeconds[n-1])*time.Second); err != nil {
				break
			}
		}
		if e.Now().Sub(start) >= time.Duration(p.ReadonlyTotalTimeoutSeconds)*time.Second {
			break
		}
	}
	kind := Classify(last)
	if parentCtx.Err() != nil {
		kind = "cancelled"
	} else if ctx.Err() != nil || e.Now().Sub(start) >= time.Duration(p.ReadonlyTotalTimeoutSeconds)*time.Second {
		kind = "transport_exhausted"
	}
	if kind == "transient_transport" && len(last.Stdout) == 0 && !last.StdoutTruncated {
		kind = "transport_exhausted"
	}
	return nil, &Error{Kind: kind, Reason: DiagnosticReason(last), Attempts: attempts, ExitCode: last.ExitCode}
}

type ExecRunner struct {
	// Prepare attaches a caller-owned lifetime guard before starting SSH.
	// It must preserve argument boundaries and the pinned SSH transport.
	Prepare func(context.Context, *exec.Cmd) error
}
type bounded struct {
	data      []byte
	max       int
	truncated bool
}

func (b *bounded) Write(p []byte) (int, error) {
	n := len(p)
	left := b.max - len(b.data)
	if left > 0 {
		if left > n {
			left = n
		}
		b.data = append(b.data, p[:left]...)
	}
	if left < n {
		b.truncated = true
	}
	return n, nil
}
func (runner ExecRunner) Run(ctx context.Context, args []string, stdin []byte, maxOut, maxErr int) Result {
	if len(args) == 0 {
		return Result{Err: context.Canceled, ExitCode: -1}
	}
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	if runner.Prepare != nil {
		if err := runner.Prepare(ctx, cmd); err != nil {
			return Result{Err: err, ExitCode: -1}
		}
	}
	cmd.Stdin = strings.NewReader(string(stdin))
	out := &bounded{max: maxOut}
	stderr := &bounded{max: maxErr}
	cmd.Stdout = out
	cmd.Stderr = stderr
	err := cmd.Run()
	rc := 0
	if err != nil {
		rc = 255
		if x, ok := err.(*exec.ExitError); ok {
			rc = x.ExitCode()
		}
	}
	return Result{Stdout: out.data, Stderr: stderr.data, ExitCode: rc, Err: err, StdoutTruncated: out.truncated}
}
func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func safeRole(role string) string {
	switch role {
	case "bridge", "exit", "database", "primary":
		return role
	default:
		return "remote"
	}
}
