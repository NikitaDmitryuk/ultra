package operatorssh

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	results []Result
	calls   int
}

func (f *fakeRunner) Run(context.Context, []string, []byte, int, int) Result {
	r := f.results[f.calls]
	f.calls++
	return r
}
func TestPolicyMatchesSharedJSON(t *testing.T) {
	b, e := os.ReadFile("../../deploy/recovery/ssh_policy.json")
	if e != nil {
		t.Fatal(e)
	}
	var p Policy
	if e = json.Unmarshal(b, &p); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(p, DefaultPolicy) {
		t.Fatalf("Go policy differs from JSON: %#v", p)
	}
}
func TestReadOnlyRetriesOnlyEmptyOutputTransientTransport(t *testing.T) {
	f := &fakeRunner{
		results: []Result{
			{ExitCode: 255, Stderr: []byte("Connection reset by peer")},
			{ExitCode: 255, Stderr: []byte("banner exchange: Connection timed out")},
			{ExitCode: 0, Stdout: []byte("ok")},
		},
	}
	sleeps := 0
	logs := 0
	var reasons []string
	e := Executor{
		Runner: f,
		Sleep:  func(context.Context, time.Duration) error { sleeps++; return nil },
		Log: func(_ string, _, _, _ int, _, reason string, _ time.Duration) {
			logs++
			reasons = append(reasons, reason)
		},
	}
	out, err := e.ReadOnly(context.Background(), "bridge", []string{"ssh", "host", "true"}, nil)
	if err != nil || string(out) != "ok" || f.calls != 3 || sleeps != 2 || logs != 3 {
		t.Fatalf("out=%q err=%v calls=%d sleeps=%d logs=%d", out, err, f.calls, sleeps, logs)
	}
	if !reflect.DeepEqual(reasons, []string{"reset", "timeout", "unknown"}) {
		t.Fatalf("reasons=%v", reasons)
	}
}
func TestReadOnlyDoesNotRetryProgramAuthOrAnyOutput(t *testing.T) {
	cases := []Result{
		{ExitCode: 255, Stderr: []byte("Permission denied")},
		{ExitCode: 255, Stderr: []byte("remote command failed")},
		{ExitCode: 255, Stderr: []byte("Connection reset"), Stdout: []byte("partial")},
	}
	for _, r := range cases {
		f := &fakeRunner{results: []Result{r}}
		e := Executor{Runner: f, Sleep: func(context.Context, time.Duration) error { t.Fatal("unexpected sleep"); return nil }}
		_, err := e.ReadOnly(context.Background(), "exit", []string{"ssh"}, nil)
		if err == nil || f.calls != 1 {
			t.Fatalf("err=%v calls=%d", err, f.calls)
		}
	}
}

func TestPolicyOpenSSHArguments(t *testing.T) {
	probe := DefaultPolicy.Options("probe")
	mutate := DefaultPolicy.Options("mutate")
	if !reflect.DeepEqual(
		probe,
		[]string{
			"-o",
			"ConnectTimeout=15",
			"-o",
			"ServerAliveInterval=5",
			"-o",
			"ServerAliveCountMax=2",
			"-o",
			"StrictHostKeyChecking=yes",
			"-o",
			"UpdateHostKeys=no",
		},
	) {
		t.Fatalf("probe args: %v", probe)
	}
	if mutate[1] != "ConnectTimeout=30" {
		t.Fatalf("mutation args: %v", mutate)
	}
}

type runnerFunc func(context.Context, []string, []byte, int, int) Result

func (f runnerFunc) Run(ctx context.Context, args []string, stdin []byte, maxOut, maxErr int) Result {
	return f(ctx, args, stdin, maxOut, maxErr)
}

func TestReadOnlyRejectsTruncatedSuccess(t *testing.T) {
	f := &fakeRunner{results: []Result{{ExitCode: 0, Stdout: []byte("partial"), StdoutTruncated: true}}}
	e := Executor{Runner: f}
	out, err := e.ReadOnly(context.Background(), "bridge", []string{"ssh"}, nil)
	var remoteErr *Error
	if out != nil || !errors.As(err, &remoteErr) || remoteErr.Kind != "output_invalid" || f.calls != 1 {
		t.Fatalf("out=%q err=%v calls=%d", out, err, f.calls)
	}
}

func TestReadOnlyDoesNotRetryProgramExitThatMentionsTransport(t *testing.T) {
	f := &fakeRunner{results: []Result{{ExitCode: 1, Stderr: []byte("connection reset by peer")}}}
	e := Executor{Runner: f, Sleep: func(context.Context, time.Duration) error { t.Fatal("unexpected retry delay"); return nil }}
	_, err := e.ReadOnly(context.Background(), "bridge", []string{"ssh"}, nil)
	var remoteErr *Error
	if !errors.As(err, &remoteErr) || remoteErr.Kind != "program_failure" || f.calls != 1 {
		t.Fatalf("err=%v calls=%d", err, f.calls)
	}
}

func TestReadOnlyTreatsHostKeyAndAuthenticationAsPermanent(t *testing.T) {
	for _, message := range []string{"Permission denied (publickey)", "Host key verification failed"} {
		f := &fakeRunner{results: []Result{{ExitCode: 255, Stderr: []byte(message)}}}
		e := Executor{Runner: f, Sleep: func(context.Context, time.Duration) error { t.Fatal("unexpected retry delay"); return nil }}
		_, err := e.ReadOnly(context.Background(), "exit", []string{"ssh"}, nil)
		var remoteErr *Error
		if !errors.As(err, &remoteErr) || remoteErr.Kind != "permanent" || f.calls != 1 {
			t.Fatalf("message=%q err=%v calls=%d", message, err, f.calls)
		}
	}
}

func TestReadOnlyDistinguishesParentCancelFromTotalTimeout(t *testing.T) {
	t.Run("parent cancel", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		f := runnerFunc(func(context.Context, []string, []byte, int, int) Result {
			cancel()
			return Result{ExitCode: 255, Stderr: []byte("Connection reset")}
		})
		e := Executor{Runner: f}
		_, err := e.ReadOnly(ctx, "bridge", []string{"ssh"}, nil)
		var remoteErr *Error
		if !errors.As(err, &remoteErr) || remoteErr.Kind != "cancelled" {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("internal total budget", func(t *testing.T) {
		p := DefaultPolicy
		p.ReadonlyTotalTimeoutSeconds = 1
		p.ReadonlyAttemptTimeoutSeconds = 10
		now := time.Unix(1, 0)
		f := runnerFunc(func(context.Context, []string, []byte, int, int) Result {
			now = now.Add(2 * time.Second)
			return Result{ExitCode: 255, Stderr: []byte("Connection reset")}
		})
		e := Executor{
			Policy: p,
			Runner: f,
			Now:    func() time.Time { return now },
			Sleep:  func(context.Context, time.Duration) error { return nil },
		}
		_, err := e.ReadOnly(context.Background(), "bridge", []string{"ssh"}, nil)
		var remoteErr *Error
		if !errors.As(err, &remoteErr) || remoteErr.Kind != "transport_exhausted" {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestReadOnlyRetriesAttemptDeadlineWithoutWaiting(t *testing.T) {
	calls := 0
	f := runnerFunc(func(context.Context, []string, []byte, int, int) Result {
		calls++
		if calls == 1 {
			return Result{ExitCode: 255, Err: context.DeadlineExceeded}
		}
		return Result{ExitCode: 0, Stdout: []byte("ok")}
	})
	e := Executor{Runner: f, Sleep: func(context.Context, time.Duration) error { return nil }}
	out, err := e.ReadOnly(context.Background(), "bridge", []string{"ssh"}, nil)
	if err != nil || string(out) != "ok" || calls != 2 {
		t.Fatalf("out=%q err=%v calls=%d", out, err, calls)
	}
}

func TestClassifyRequiresKnownTransportEvidence(t *testing.T) {
	for _, stderr := range []string{
		"banner exchange: remote sent no data",
		"kex_exchange_identification: negotiation stopped unexpectedly",
		"key exchange failed",
		"ssh_exchange_identification: unexpected protocol version",
	} {
		if got := Classify(Result{ExitCode: 255, Stderr: []byte(stderr)}); got != "program_failure" {
			t.Errorf("Classify(%q)=%q, want program_failure", stderr, got)
		}
	}
	if got := Classify(Result{ExitCode: 255, Stderr: []byte("banner exchange: Connection reset by peer")}); got != "transient_transport" {
		t.Fatalf("known reset marker classified as %q", got)
	}
	if got := Classify(Result{ExitCode: 255, Stderr: []byte("server closed connection")}); got != "program_failure" {
		t.Fatalf("unconfirmed close classified as %q", got)
	}
}

func TestReadOnlyDoesNotRetryUnknownNegotiationOrUnknown255(t *testing.T) {
	for _, stderr := range []string{"kex_exchange_identification: unknown banner", "unexpected ssh failure"} {
		f := &fakeRunner{results: []Result{{ExitCode: 255, Stderr: []byte(stderr)}}}
		e := Executor{Runner: f, Sleep: func(context.Context, time.Duration) error { t.Fatal("unexpected retry delay"); return nil }}
		_, err := e.ReadOnly(context.Background(), "bridge", []string{"ssh"}, nil)
		var remoteErr *Error
		if !errors.As(err, &remoteErr) || remoteErr.Kind != "program_failure" || remoteErr.Reason != "unknown" || f.calls != 1 {
			t.Errorf("stderr=%q err=%v calls=%d", stderr, err, f.calls)
		}
	}
}

func TestErrorPreservesOnlySafeDiagnosticReason(t *testing.T) {
	r := Result{ExitCode: 255, Stderr: []byte("Connection reset by peer; secret-value")}
	err := &Error{Kind: "transport_exhausted", Reason: DiagnosticReason(r)}
	if got := err.Error(); got != "SSH read-only transport retries exhausted (reset)" || strings.Contains(got, "secret-value") {
		t.Fatalf("Error()=%q", got)
	}
	if got := (&Error{Kind: "unexpected", Reason: "raw stderr"}).Error(); got != "SSH read-only remote command failed (program_failure, unknown)" {
		t.Fatalf("unsafe error fields escaped: %q", got)
	}
}
