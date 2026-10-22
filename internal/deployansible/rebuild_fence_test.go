package deployansible

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type recoveryFixture struct {
	directory string
	gate      *lifecycleGate
	key       ed25519.PrivateKey
	request   SignedRecoveryFenceRequest
}

func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	primary := RecoveryPrimary{Provider: "fixture", AccountID: "account", InstanceID: "primary", SystemIdentifier: "123", DatabaseOID: "42"}
	anchor := RecoveryAnchor{Version: 1, SignerID: "independent-executor", PublicKey: public, Primary: primary}
	raw, _ := json.Marshal(anchor)
	if err = os.WriteFile(filepath.Join(directory, "recovery-anchor.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	gate, err := openLifecycleGate(directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.close)
	now := time.Now().Unix()
	f := &recoveryFixture{directory: directory, gate: gate, key: key, request: SignedRecoveryFenceRequest{Request: RecoveryFenceRequest{
		Version: 1, SignerID: anchor.SignerID, RecoveryID: "11111111-1111-1111-1111-111111111111", Nonce: strings.Repeat("n", 32), IssuedAt: now - 10, ExpiresAt: now + 3600,
		ManualJournalSHA256: strings.Repeat(
			"1",
			64,
		), PredecessorSHA256: []string{strings.Repeat("2", 64)}, CandidateSHA256: strings.Repeat("3", 64), FleetSHA256: strings.Repeat("4", 64), Primary: primary,
		Targets: []RecoveryTarget{{Provider: "fixture", AccountID: "account", InstanceID: "bridge", Role: "bridge"}},
	}}}
	f.signRequest(t)
	return f
}
func (f *recoveryFixture) signRequest(t *testing.T) {
	t.Helper()
	raw, err := RecoveryFenceSigningBytes(f.request.Request)
	if err != nil {
		t.Fatal(err)
	}
	f.request.Signature = ed25519.Sign(f.key, raw)
}
func (f *recoveryFixture) completion(t *testing.T) SignedRecoveryFenceCompletion {
	t.Helper()
	raw, _ := RecoveryFenceSigningBytes(f.request.Request)
	c := RecoveryFenceCompletion{
		Version:       1,
		SignerID:      f.request.Request.SignerID,
		RequestSHA256: recoveryHash(raw),
		Nonce:         f.request.Request.Nonce,
		CompletedAt:   time.Now().Unix(),
		ExpiresAt:     time.Now().Unix() + 3600,
		TargetOutcomesSHA256: strings.Repeat(
			"5",
			64,
		),
		PrimaryVerificationSHA256: strings.Repeat("6", 64),
		BackupReceiptSHA256:       strings.Repeat("7", 64),
		TunnelEscrowSHA256:        strings.Repeat("8", 64),
		ControllerHandoffSHA256:   strings.Repeat("9", 64),
	}
	signed, _ := RecoveryCompletionSigningBytes(c)
	return SignedRecoveryFenceCompletion{Completion: c, Signature: ed25519.Sign(f.key, signed)}
}
func requireRecoveryCode(t *testing.T, r Response, code string) {
	t.Helper()
	if r.Code != code {
		t.Fatalf("response=%+v, want code %s", r, code)
	}
}
func requireRecoveryBlocked(t *testing.T, directory string) {
	t.Helper()
	release, err := recoveryAdmission(directory)
	if release != nil {
		release()
	}
	if !errors.Is(err, errRecoveryFenced) {
		t.Fatalf("admission=%v, want recovery fence", err)
	}
}

func TestRecoveryFenceLifecycleAndExecutionEntrypoints(t *testing.T) {
	f := newRecoveryFixture(t)
	r := f.gate.importRecoveryFence(f.request)
	if r.Code != "recovery_independent_quiescence_required" {
		t.Fatalf("import=%+v", r)
	}
	id := f.request.Request.RecoveryID
	checks := map[string]func() Response{
		"apply":     func() Response { return f.gate.transition(id, "applying") },
		"resume":    func() Response { return f.gate.transitionWithLock(id, "applying", nil, true) },
		"check":     func() Response { return f.gate.transition(id, "checking") },
		"release":   func() Response { return f.gate.transition(id, "released") },
		"attach":    func() Response { return f.gate.attach(id) },
		"retire":    func() Response { return f.gate.retire(id) },
		"supersede": func() Response { return f.gate.supersede(id, "22222222-2222-2222-2222-222222222222", nil) },
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) { requireRecoveryCode(t, check(), "recovery_fenced") })
	}
	if f.gate.phase() != "recovery_fenced" {
		t.Fatal("topology status did not preserve fence")
	}
	if !f.gate.blocked() {
		t.Fatal("fence not reflected in service admission")
	}
	for _, operation := range []string{"configure-exit", "reconcile", "configure-bot"} {
		lock, err := f.gate.jobLock(operation)
		if lock != nil {
			_ = lock.Close()
		}
		if !errors.Is(err, errRecoveryFenced) {
			t.Fatalf("job %s=%v", operation, err)
		}
	}
	if _, release, err := WithOperationLock(context.Background(), f.directory); err == nil {
		release()
		t.Fatal("direct lease passed")
	}
	directory := filepath.Join(f.directory, "attempt")
	if _, err := Execute(context.Background(), directory, "/bin/false", "/bin/false"); !errors.Is(err, errRecoveryFenced) {
		t.Fatalf("direct Execute=%v", err)
	}
	for _, operation := range []string{"inspect-bootstrap", "reconcile", "bootstrap-postgres", "bootstrap-bridge"} {
		if _, err := RunLocal(context.Background(), operation, map[string]any{}, map[string]any{}, directory, "/bin/false", "/bin/false"); !errors.Is(
			err,
			errRecoveryFenced,
		) {
			t.Fatalf("local %s=%v", operation, err)
		}
	}
	if _, err := os.Stat(directory); !os.IsNotExist(err) {
		t.Fatal("blocked executor created attempt")
	}
}

func TestRecoveryFencePriorLeasePreventsDrainAndCompletion(t *testing.T) {
	f := newRecoveryFixture(t)
	ctx, release, err := WithOperationLock(context.Background(), f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	requireRecoveryCode(t, f.gate.importRecoveryFence(f.request), "recovery_drain_pending")
	requireRecoveryBlocked(t, f.directory)
	j, _, err := loadRecoveryFence(f.directory)
	if err != nil || j.Phase != "draining" {
		t.Fatalf("write ahead journal=%+v %v", j, err)
	}
	if _, err = RunLocal(ctx, "reconcile", map[string]any{}, map[string]any{}, filepath.Join(f.directory, "attempt"), "/bin/false", "/bin/false"); !errors.Is(
		err,
		errRecoveryFenced,
	) {
		t.Fatalf("previous lease stage=%v", err)
	}
	if _, err = Execute(ctx, filepath.Join(f.directory, "job"), "/bin/false", "/bin/false"); !errors.Is(err, errRecoveryFenced) {
		t.Fatalf("previous worker lease=%v", err)
	}
	completion := f.completion(t)
	requireRecoveryCode(t, f.gate.completeRecoveryFence(completion), "recovery_completion_unsupported")
	requireRecoveryBlocked(t, f.directory)
	release()
	if r := f.gate.importRecoveryFence(f.request); r.Code != "recovery_independent_quiescence_required" {
		t.Fatalf("drain retry=%+v", r)
	}
	requireRecoveryBlocked(t, f.directory) // Draining alone never releases admissions.
	requireRecoveryCode(t, f.gate.completeRecoveryFence(completion), "recovery_completion_unsupported")
	requireRecoveryBlocked(t, f.directory)
	requireRecoveryCode(t, f.gate.importRecoveryFence(f.request), "recovery_independent_quiescence_required")
	// A changed request cannot replace an already active durable fence.
	f.request.Request.Nonce = strings.Repeat("z", 32)
	f.signRequest(t)
	requireRecoveryCode(t, f.gate.importRecoveryFence(f.request), "recovery_fenced")
}

func TestRecoveryFenceRetainedBrokerLockAndRestart(t *testing.T) {
	f := newRecoveryFixture(t)
	id := f.request.Request.RecoveryID
	if r := f.gate.transition(id, "applying"); r.State != "applying" {
		t.Fatal(r)
	}
	attached := f.gate.attach(id)
	if attached.State != "applying" {
		t.Fatal(attached)
	}
	defer closeInputs(attached.leaseOutputs)
	lifecycleBefore, err := os.ReadFile(filepath.Join(f.directory, "lifecycle.json"))
	if err != nil {
		t.Fatal(err)
	}
	requireRecoveryCode(t, f.gate.importRecoveryFence(f.request), "recovery_drain_pending")
	if f.gate.lock != nil {
		t.Fatal("broker did not release its own OFD")
	}
	f.gate.close()
	restarted, err := openLifecycleGate(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.close()
	if restarted.lock != nil || restarted.current.ID != id || restarted.current.Phase != "applying" {
		t.Fatalf("restart gate=%+v", restarted.current)
	}
	requireRecoveryCode(t, restarted.attach(id), "recovery_fenced")
	requireRecoveryCode(t, restarted.importRecoveryFence(f.request), "recovery_drain_pending")
	requireRecoveryCode(t, restarted.completeRecoveryFence(f.completion(t)), "recovery_completion_unsupported")
	closeInputs(attached.leaseOutputs)
	if r := restarted.importRecoveryFence(f.request); r.Code != "recovery_independent_quiescence_required" {
		t.Fatal(r)
	}
	requireRecoveryBlocked(t, f.directory)
	requireRecoveryCode(t, restarted.completeRecoveryFence(f.completion(t)), "recovery_completion_unsupported")
	lifecycleAfter, _ := os.ReadFile(filepath.Join(f.directory, "lifecycle.json"))
	if string(lifecycleBefore) != string(lifecycleAfter) {
		t.Fatal("recovery rewrote original lifecycle journal")
	}
	// Unsupported completion preserves both recovery and original ownership.
	if !restarted.blocked() {
		t.Fatal("old lifecycle ownership lost")
	}
}

func TestRecoveryFenceRejectsUntrustedRequests(t *testing.T) {
	tests := map[string]func(*testing.T, *recoveryFixture){
		"tampered": func(t *testing.T, f *recoveryFixture) { f.request.Request.CandidateSHA256 = strings.Repeat("a", 64) },
		"wrong-key": func(t *testing.T, f *recoveryFixture) {
			_, f.key, _ = ed25519.GenerateKey(rand.Reader)
			f.signRequest(t)
		},
		"wrong-signer": func(t *testing.T, f *recoveryFixture) { f.request.Request.SignerID = "request-key"; f.signRequest(t) },
		"expired": func(t *testing.T, f *recoveryFixture) {
			f.request.Request.ExpiresAt = time.Now().Unix() - 1
			f.signRequest(t)
		},
		"future": func(t *testing.T, f *recoveryFixture) {
			f.request.Request.IssuedAt = time.Now().Unix() + 1
			f.signRequest(t)
		},
		"journal": func(t *testing.T, f *recoveryFixture) { f.request.Request.ManualJournalSHA256 = ""; f.signRequest(t) },
		"predecessor": func(t *testing.T, f *recoveryFixture) {
			f.request.Request.PredecessorSHA256 = []string{"bad"}
			f.signRequest(t)
		},
		"missing-chain": func(t *testing.T, f *recoveryFixture) { f.request.Request.PredecessorSHA256 = nil; f.signRequest(t) },
		"primary-target": func(t *testing.T, f *recoveryFixture) {
			f.request.Request.Targets[0].InstanceID = "primary"
			f.signRequest(t)
		},
		"db-role": func(t *testing.T, f *recoveryFixture) {
			f.request.Request.Targets[0].Role = "database"
			f.signRequest(t)
		},
		"primary-identity": func(t *testing.T, f *recoveryFixture) {
			f.request.Request.Primary.SystemIdentifier = "changed"
			f.signRequest(t)
		},
		"no-anchor": func(t *testing.T, f *recoveryFixture) {
			if err := os.Remove(filepath.Join(f.directory, "recovery-anchor.json")); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRecoveryFixture(t)
			mutate(t, f)
			if r := f.gate.importRecoveryFence(f.request); r.Code == "" {
				t.Fatalf("accepted request: %+v", r)
			}
			if _, err := os.Stat(filepath.Join(f.directory, "recovery-fence.json")); !os.IsNotExist(err) {
				t.Fatal("invalid request wrote fence")
			}
		})
	}
}

func TestRecoveryFenceCompletionCannotRelease(t *testing.T) {
	tests := map[string]func(*testing.T, *recoveryFixture, *SignedRecoveryFenceCompletion){
		"tamper": func(t *testing.T, f *recoveryFixture, s *SignedRecoveryFenceCompletion) {
			s.Completion.BackupReceiptSHA256 = strings.Repeat("a", 64)
		},
		"wrong-request": func(t *testing.T, f *recoveryFixture, s *SignedRecoveryFenceCompletion) {
			s.Completion.RequestSHA256 = strings.Repeat("b", 64)
			raw, _ := RecoveryCompletionSigningBytes(s.Completion)
			s.Signature = ed25519.Sign(f.key, raw)
		},
		"wrong-nonce": func(t *testing.T, f *recoveryFixture, s *SignedRecoveryFenceCompletion) {
			s.Completion.Nonce = strings.Repeat("z", 32)
			raw, _ := RecoveryCompletionSigningBytes(s.Completion)
			s.Signature = ed25519.Sign(f.key, raw)
		},
		"expired": func(t *testing.T, f *recoveryFixture, s *SignedRecoveryFenceCompletion) {
			s.Completion.CompletedAt = time.Now().Unix() - 5
			s.Completion.ExpiresAt = time.Now().Unix() - 1
			raw, _ := RecoveryCompletionSigningBytes(s.Completion)
			s.Signature = ed25519.Sign(f.key, raw)
		},
		"wrong-key": func(t *testing.T, f *recoveryFixture, s *SignedRecoveryFenceCompletion) {
			_, key, _ := ed25519.GenerateKey(rand.Reader)
			raw, _ := RecoveryCompletionSigningBytes(s.Completion)
			s.Signature = ed25519.Sign(key, raw)
		},
		"unsigned": func(t *testing.T, f *recoveryFixture, s *SignedRecoveryFenceCompletion) { s.Signature = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			f := newRecoveryFixture(t)
			if r := f.gate.importRecoveryFence(f.request); r.Code != "recovery_independent_quiescence_required" {
				t.Fatal(r)
			}
			completion := f.completion(t)
			mutate(t, f, &completion)
			if r := f.gate.completeRecoveryFence(completion); r.Code == "" {
				t.Fatalf("accepted completion: %+v", r)
			}
			requireRecoveryBlocked(t, f.directory)
			// Expiry cannot clear an already imported request.
			f.request.Request.ExpiresAt = time.Now().Unix() - 1
			f.signRequest(t)
			requireRecoveryBlocked(t, f.directory)
		})
	}
}

func TestRecoveryFenceCorruptStateAndAnchorFailClosed(t *testing.T) {
	for _, kind := range []string{"journal", "anchor", "missing-anchor", "unsigned-release"} {
		t.Run(kind, func(t *testing.T) {
			f := newRecoveryFixture(t)
			if r := f.gate.importRecoveryFence(f.request); r.Code != "recovery_independent_quiescence_required" {
				t.Fatal(r)
			}
			switch kind {
			case "journal":
				if err := os.WriteFile(filepath.Join(f.directory, "recovery-fence.json"), []byte("{"), 0600); err != nil {
					t.Fatal(err)
				}
			case "anchor":
				if err := os.WriteFile(filepath.Join(f.directory, "recovery-anchor.json"), []byte("{}"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-anchor":
				if err := os.Remove(filepath.Join(f.directory, "recovery-anchor.json")); err != nil {
					t.Fatal(err)
				}
			case "unsigned-release":
				j, _, _ := loadRecoveryFence(f.directory)
				j.Phase = "completed"
				if err := f.gate.saveRecoveryFence(j); err != nil {
					t.Fatal(err)
				}
			}
			requireRecoveryBlocked(t, f.directory)
			restarted, err := openLifecycleGate(f.directory)
			if err != nil {
				t.Fatal(err)
			}
			defer restarted.close()
			if !restarted.blocked() {
				t.Fatal("restart reopened corrupt fence")
			}
		})
	}
}

func TestRecoveryFenceUnprovisionedBehaviorPreserved(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	admission, err := recoveryAdmission(directory)
	if err != nil {
		t.Fatal(err)
	}
	admission()
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unprovisioned admission changed directory: %v %v", entries, err)
	}
	_, release, err := WithOperationLock(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	release()
}

// A local socketpair exercises the real peer-credential and message handler
// without starting a listener or any executor.
func recoveryBrokerResponse(t *testing.T, f *recoveryFixture, message Message) Response {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	unixConn := func(fd int) *net.UnixConn {
		file := os.NewFile(uintptr(fd), "recovery-test-socket")
		conn, err := net.FileConn(file)
		_ = file.Close()
		if err != nil {
			t.Fatal(err)
		}
		return conn.(*net.UnixConn)
	}
	server := unixConn(fds[0])
	client := unixConn(fds[1])
	defer server.Close() //nolint:errcheck
	defer client.Close() //nolint:errcheck
	_ = server.SetDeadline(time.Now().Add(5 * time.Second))
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	raw, err := json.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	if err = sendRequest(client, append(raw, '\n'), nil); err != nil {
		t.Fatal(err)
	}
	return handleConnection(server, f.directory, uint32(os.Getuid()), f.gate)
}
func TestRecoveryFenceBrokerAdmission(t *testing.T) {
	f := newRecoveryFixture(t)
	if r := f.gate.importRecoveryFence(f.request); r.Code != "recovery_independent_quiescence_required" {
		t.Fatal(r)
	}
	id := f.request.Request.RecoveryID
	requireRecoveryCode(t, recoveryBrokerResponse(t, f, Message{Action: "submit", ID: id}), "recovery_fenced")
	requireRecoveryCode(t, recoveryBrokerResponse(t, f, Message{Action: "ready"}), "lifecycle_busy")
	if r := recoveryBrokerResponse(t, f, Message{Action: "lifecycle-status"}); r.State != "recovery_fenced" {
		t.Fatal(r)
	}
	for _, action := range []string{"lease-attach", "lease-retire", "lease-release", "lease-checking", "lease-resume", "lease-applying"} {
		expected := "recovery_fenced"
		if os.Getuid() != 0 {
			expected = "controller_access_denied"
		}
		requireRecoveryCode(t, recoveryBrokerResponse(t, f, Message{Action: action, ID: id}), expected)
	}
	if os.Getuid() != 0 {
		requireRecoveryCode(
			t,
			recoveryBrokerResponse(t, f, Message{Action: "recovery-fence-import", RecoveryFence: &f.request}),
			"controller_access_denied",
		)
	}
}
func TestRecoveryFenceExpiredActiveRequestAndUnsupportedCompletionRestart(t *testing.T) {
	f := newRecoveryFixture(t)
	if r := f.gate.importRecoveryFence(f.request); r.Code != "recovery_independent_quiescence_required" {
		t.Fatal(r)
	}
	// Simulate passage of time without weakening the signatures or sleeping.
	j, _, err := loadRecoveryFence(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	f.request.Request.ExpiresAt = time.Now().Unix() - 1
	f.signRequest(t)
	j.Request = f.request
	raw, _ := RecoveryFenceSigningBytes(f.request.Request)
	j.RequestSHA256 = recoveryHash(raw)
	if err = f.gate.saveRecoveryFence(j); err != nil {
		t.Fatal(err)
	}
	requireRecoveryCode(t, f.gate.importRecoveryFence(f.request), "expired_recovery_request")
	requireRecoveryBlocked(t, f.directory)
	restarted, err := openLifecycleGate(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.close()
	requireRecoveryCode(t, restarted.transition(f.request.Request.RecoveryID, "released"), "recovery_fenced")
	requireRecoveryCode(t, restarted.completeRecoveryFence(f.completion(t)), "recovery_completion_unsupported")
	restarted.close()
	after, err := openLifecycleGate(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer after.close()
	if !after.blocked() {
		t.Fatal("unsupported completion released fence on restart")
	}
	requireRecoveryBlocked(t, f.directory)
}

// Invoked only as an isolated test subprocess. This exercises the actual direct
// Execute entrypoint and its real isolateCommand process-group behavior.
func TestRecoveryFenceOrphanedExecutorHelper(t *testing.T) {
	directory := os.Getenv("ULTRA_RECOVERY_TEST_ORPHAN_DIR")
	if directory == "" {
		return
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Execute(context.Background(), filepath.Join(directory, "attempt"), python, "/bin/false")
	if err != nil {
		t.Fatal(err)
	}
}

func TestRecoveryFenceOrphanedExecutorCannotProveDrain(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 unavailable")
	}
	f := newRecoveryFixture(t)
	bundle := filepath.Join(f.directory, "attempt", "bundle")
	if err := os.MkdirAll(bundle, 0700); err != nil {
		t.Fatal(err)
	}
	// A synthetic controller survives its Go wrapper. Its local write is the
	// mutation witness; no Ansible, SSH, provider, or database command runs.
	source := `import os,pathlib,sys,time
root=pathlib.Path(sys.argv[sys.argv.index('--job')+1]).parent
(root/'child-ready').write_text(str(os.getpid()))
deadline=time.monotonic()+5
while time.monotonic()<deadline:
    if (root/'mutate').exists():
        (root/'mutation-done').write_text('orphan still executes')
        break
    time.sleep(0.005)
`
	if err := os.WriteFile(filepath.Join(bundle, "controller.py"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}

	raw := []byte(`{}`)
	if err := writePrivate(filepath.Join(f.directory, "attempt", "request.json"), raw); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(f.directory, "attempt", "job.json"), map[string]any{"schema_version": 1, "operation": "configure-exit", "request_sha256": executionHash(raw), "binary_sha256": executionHash(raw)}); err != nil {
		t.Fatal(err)
	}
	holder := exec.Command(os.Args[0], "-test.run=^TestRecoveryFenceOrphanedExecutorHelper$", "-test.timeout=10s")
	holder.Env = []string{"ULTRA_RECOVERY_TEST_ORPHAN_DIR=" + f.directory, "PATH=/usr/bin:/bin"}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Process.Kill() }()
	await := func(name string) []byte {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if raw, err := os.ReadFile(filepath.Join(f.directory, name)); err == nil {
				return raw
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("executor did not produce %s", name)
		return nil
	}
	childPID, err := strconv.Atoi(string(await("child-ready")))
	if err != nil || childPID <= 0 {
		t.Fatalf("invalid child PID: %v", err)
	}
	if lock, err := controllerLock(filepath.Join(f.directory, "infrastructure.lock")); err == nil {
		_ = lock.Close()
		t.Fatal("live Go executor did not hold infrastructure lock")
	}
	if err = holder.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err = holder.Wait(); err == nil {
		t.Fatal("wrapper did not die by SIGKILL")
	}
	// The Go-held CLOEXEC OFD is now free, while its controller remains runnable.
	lock, err := controllerLock(filepath.Join(f.directory, "infrastructure.lock"))
	if err != nil {
		t.Fatalf("dead wrapper still holds lock: %v", err)
	}
	_ = lock.Close()
	requireRecoveryCode(t, f.gate.importRecoveryFence(f.request), "recovery_independent_quiescence_required")
	if err = os.WriteFile(filepath.Join(f.directory, "mutate"), []byte("go"), 0600); err != nil {
		t.Fatal(err)
	}
	await("mutation-done")
	requireRecoveryCode(t, f.gate.completeRecoveryFence(f.completion(t)), "recovery_completion_unsupported")
	requireRecoveryBlocked(t, f.directory)
	j, _, err := loadRecoveryFence(f.directory)
	if err != nil || j.Phase != "draining" {
		t.Fatalf("orphan received drained state: %+v %v", j, err)
	}
	restarted, err := openLifecycleGate(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.close()
	if !restarted.blocked() {
		t.Fatal("restart released fence after orphan execution")
	}
}

func TestRecoveryFenceLegacySignedCompletionFailsClosed(t *testing.T) {
	f := newRecoveryFixture(t)
	requireRecoveryCode(t, f.gate.importRecoveryFence(f.request), "recovery_independent_quiescence_required")
	j, _, err := loadRecoveryFence(f.directory)
	if err != nil {
		t.Fatal(err)
	}
	signed := f.completion(t)
	j.Phase = "completed"
	j.Completion = &signed
	if err = f.gate.saveRecoveryFence(j); err != nil {
		t.Fatal(err)
	}
	requireRecoveryBlocked(t, f.directory)
	if r := f.gate.completeRecoveryFence(signed); r.Code == "" {
		t.Fatal("legacy completion accepted")
	}
}
