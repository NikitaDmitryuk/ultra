//go:build linux

package deployansible

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestClientFailureIncludesSavedDiagnosticCode(t *testing.T) {
	for _, code := range []string{"ssh_pin_mismatch", "ingress_tls_hostname_mismatch", "task_failed", ""} {
		t.Run("code="+code, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "worker.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close() //nolint:errcheck
			response := Response{Code: "ansible_failed", Diagnostic: Diagnostic{
				Node: "bridge", Stage: "Verify service readiness", Code: code,
			}}
			done := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptUnix()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close() //nolint:errcheck
				_, inputs, err := receiveRequest(conn)
				closeInputs(inputs)
				if err == nil {
					var raw []byte
					raw, err = json.Marshal(response)
					if err == nil {
						err = sendRequest(conn, append(raw, '\n'), nil)
					}
				}
				done <- err
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			saved, err := (Client{Socket: socket}).exchange(ctx, Message{Action: "status"})
			want := "ansible_failed (bridge: Verify service readiness"
			if code != "" {
				want += "; " + code
			}
			want += ")"
			if err == nil || err.Error() != want || saved.Diagnostic != response.Diagnostic {
				t.Fatalf("failure = %v, diagnostic = %+v; want %s, %+v", err, saved.Diagnostic, want, response.Diagnostic)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestWorkerContinuesAfterClientDisconnectAndRestart(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	binary, request := fixture(t)
	root := t.TempDir()
	socket := filepath.Join(root, "worker.sock")
	state := filepath.Join(root, "state")
	stub := filepath.Join(root, "ansible-playbook")
	// Re-seal this copied controller before any fence/dispatch, because the
	// existing private namespace resolver rewrites its production-root constant.
	savedNamespace := executionFenceDirectory
	t.Cleanup(func() { executionFenceDirectory = savedNamespace })
	executionFenceDirectory = func(directory string) string {
		namespace := savedNamespace(directory)
		if !strings.HasPrefix(directory, state+string(os.PathSeparator)) {
			return namespace
		}
		for _, path := range []string{filepath.Join(namespace, "execution-fence.json"), filepath.Join(directory, "receipt.json")} {
			if _, e := os.Lstat(path); e == nil || !os.IsNotExist(e) {
				return namespace
			}
		}
		jobRaw, e := os.ReadFile(filepath.Join(directory, "job.json"))
		if e != nil {
			return namespace
		}
		var job struct {
			Request string `json:"request_sha256"`
		}
		if e = json.Unmarshal(jobRaw, &job); e != nil {
			t.Error(e)
			return namespace
		}
		ownership := filepath.Join(directory, "bundle.retention.json")
		if e = os.Remove(ownership); e != nil && !os.IsNotExist(e) {
			t.Error(e)
			return namespace
		}
		if e = WriteRetentionReceipt(filepath.Join(directory, "bundle"), filepath.Join(directory, "bundle"), ownership, map[string]string{"request_sha256": job.Request}); e != nil {
			t.Error(e)
		}
		return namespace
	}

	source := "#!" + python + `
import json,pathlib,sys,time
value=json.loads((pathlib.Path(sys.argv[-1][1:]).parent/'variables.json').read_text())
time.sleep(0.1)
path=pathlib.Path(value['ultra_result_file'])
path.write_text(json.dumps({'cert_pin':'b'*64}))
path.chmod(0o600)
`
	if err = os.WriteFile(stub, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	start := func() (context.CancelFunc, chan error) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- Serve(ctx, socket, state, python, stub, uint32(os.Getuid())) }()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if err := (Client{Socket: socket}).Ready(context.Background()); err == nil {
				return cancel, done
			}
			select {
			case err := <-done:
				cancel()
				t.Fatalf("worker exited: %v", err)
			default:
			}
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		t.Fatal("worker did not start")
		return nil, nil
	}
	cancel, done := start()
	client := Client{Socket: socket}
	// A peer cannot instruct the privileged worker to open pathnames. Sources
	// must arrive as already-open descriptors from that peer's credentials.
	connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	raw, err := json.Marshal(Message{Action: "submit", ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Binary: binary, Request: &request})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err = sendRequest(connection, append(raw, '\n'), nil); err != nil {
		cancel()
		t.Fatal(err)
	}
	var rejected Response
	if err = json.NewDecoder(connection).Decode(&rejected); err != nil {
		cancel()
		t.Fatal(err)
	}
	_ = connection.Close()
	if rejected.Code != "exit_request_required" {
		cancel()
		t.Fatalf("pathname-only input accepted: %s", rejected.Code)
	}
	if _, err = os.Stat(filepath.Join(state, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")); !os.IsNotExist(err) {
		cancel()
		t.Fatal("pathname-only input created a job")
	}

	id := "11111111-2222-3333-4444-555555555555"
	response, err := client.exchange(context.Background(), Message{Action: "submit", ID: id, Binary: binary, Request: &request})
	if err != nil || (response.State != "queued" && response.State != "running") {
		cancel()
		t.Fatalf("submission: %v %#v", err, response)
	}
	// The submitter is gone. Let the worker acknowledge normal completion before
	// restart; cancelling running SSH is uncertain and is fenced by other tests.
	completed, stopCompletion := context.WithTimeout(context.Background(), 5*time.Second)
	directory := filepath.Join(state, id)
	// This rootless worker exercises real RunLocal but has no systemd manager.
	// Supply synthetic containment evidence only after its real completion and
	// fence retirement; production Status has no private-namespace exception.
	ready := false
	for completed.Err() == nil {
		current, e := inspectExecutionFence(executionFenceDirectory(directory))
		if e == nil && current == nil && completedExecution(directory) {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		stopCompletion()
		cancel()
		<-done
		t.Fatal("worker did not normally complete before fixture attestation")
	}
	publishWorkerFixtureContainment(t, directory)
	if _, err = client.ConfigureExit(completed, id, binary, request); err != nil {
		stopCompletion()
		cancel()
		t.Fatal(err)
	}
	stopCompletion()
	// The submitter is gone. Restart the worker with the same persistent job.
	cancel()
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	cancel, done = start()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	result, err := client.ConfigureExit(ctx, id, binary, request)
	if err != nil || len(result.CertPin) != 64 {
		t.Fatalf("resume: %v", err)
	}
	if err = os.WriteFile(binary, []byte("different pinned binary"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = client.ConfigureExit(ctx, id, binary, request); err == nil {
		t.Fatal("different release accepted on retry")
	}
	request.Host = "192.0.2.99"
	if _, err = client.ConfigureExit(ctx, id, binary, request); err == nil {
		t.Fatal("different topology accepted on retry")
	}
}

func TestLifecycleRetirementDispatchAuthorization(t *testing.T) {
	for _, action := range []string{"lease-retire", "lease-supersede"} {
		t.Run(action, func(t *testing.T) {
			root := lifecycleTestDirectory(t)
			gate, err := openLifecycleGate(root)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.close()
			id := "11111111-2222-3333-4444-555555555555"
			if result := gate.transition(id, "applying"); result.Code != "" {
				t.Fatal(result)
			}
			socket := filepath.Join(root, "controller.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close() //nolint:errcheck
			done := make(chan Response, 1)
			go func() {
				conn, err := listener.AcceptUnix()
				if err != nil {
					done <- Response{Code: "accept_failed"}
					return
				}
				defer conn.Close() //nolint:errcheck
				done <- handleConnection(conn, root, uint32(os.Geteuid()), gate)
			}()
			conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close() //nolint:errcheck
			var inputs []*os.File
			if action == "lease-supersede" {
				inputs = []*os.File{gate.lock}
			}
			if err := sendRequest(conn, []byte(`{"action":"`+action+`","id":"`+id+`","next_id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}`+"\n"), inputs); err != nil {
				t.Fatal(err)
			}
			select {
			case result := <-done:
				if os.Geteuid() == 0 {
					if result.Code != "" || (action == "lease-retire" && (result.State != "released" || gate.blocked())) ||
						(action == "lease-supersede" && (result.State != "applying" || !gate.blocked())) {
						t.Fatal("root retirement dispatch failed", result)
					}
				} else if result.Code != "controller_access_denied" || !gate.blocked() || gate.retired[id] {
					t.Fatal("non-root retired root lifecycle", result)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("retirement dispatch timed out")
			}
		})
	}
}

func readProjectedFixture(t *testing.T, directory string) Response {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(directory, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var receipt Receipt
	if err = json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	return projectControllerReceipt(directory, raw, receipt)
}
func assertUncertainProjection(t *testing.T, response Response) {
	t.Helper()
	if response.State != "running" || response.Code != "execution_uncertain_reconciliation_required" ||
		!reflect.DeepEqual(response.Result, Result{}) ||
		response.Diagnostic != (Diagnostic{}) {
		t.Fatalf("unsafe terminal projection: %+v", response)
	}
}
func TestControllerTerminalRequiresRetiredVerifiedCleanup(t *testing.T) {
	for _, missing := range []string{"completion", "containment", "drain", "retirement"} {
		t.Run(missing, func(t *testing.T) {
			fence, proof := containmentCompletionFixture(t)
			// Unverified Status must not attempt live systemd inspection or repair.
			mockContainmentObservation(t, func(string) (map[string]string, error) {
				t.Fatal("status attempted live containment recovery")
				return nil, nil
			})
			switch missing {
			case "completion":
				if err := os.Remove(filepath.Join(fence.JobDirectory, "execution-completion.json")); err != nil {
					t.Fatal(err)
				}
			case "containment":
				if err := os.Remove(filepath.Join(fence.JobDirectory, "execution-containment.json")); err != nil {
					t.Fatal(err)
				}
			case "retirement":
				if err := completeContainedExecution(*fence, proof.Unit, nil, func(string) error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			// Except retirement, remove fence to isolate missing evidence independently.
			if missing != "retirement" {
				if err := os.Remove(filepath.Join(executionFenceDirectory(fence.JobDirectory), "execution-fence.json")); err != nil {
					t.Fatal(err)
				}
			}
			assertUncertainProjection(t, readProjectedFixture(t, fence.JobDirectory))
		})
	}
}
func TestControllerTerminalVerifiedSuccessSurvivesOtherJobFence(t *testing.T) {
	fence, proof := containmentCompletionFixture(t)
	if err := completeContainedExecution(*fence, proof.Unit, nil, func(string) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileExecutionFence(*fence); err != nil {
		t.Fatal(err)
	}
	mockContainmentObservation(t, func(string) (map[string]string, error) { t.Fatal("status attempted live observation"); return nil, nil })
	if response := readProjectedFixture(t, fence.JobDirectory); response.State != "succeeded" {
		t.Fatal(response)
	}
	next := filepath.Join(filepath.Dir(fence.JobDirectory), "different-job")
	prepareExecutionFixture(t, next)
	if _, err := beginExecution(next); err != nil {
		t.Fatal(err)
	}
	if response := readProjectedFixture(t, fence.JobDirectory); response.State != "succeeded" {
		t.Fatal(response)
	}
}
func TestControllerTerminalVerifiedNormalFailure(t *testing.T) {
	fence, proof := containmentCompletionFixture(t)
	for _, name := range []string{"receipt.json", "execution-completion.json"} {
		if err := os.Remove(filepath.Join(fence.JobDirectory, name)); err != nil {
			t.Fatal(err)
		}
	}
	terminalPath := filepath.Join(fence.JobDirectory, "execution-terminal-"+fence.Generation+".json")
	if err := writeJSON(terminalPath, map[string]any{"fence": fence, "outcome": "failed", "contacted_hosts": 1, "pending_tasks": 0, "unreachable_hosts": 0, "unmanaged_async": false}); err != nil {
		t.Fatal(err)
	}
	terminal, _ := os.ReadFile(terminalPath)
	if err := writeJSON(filepath.Join(fence.JobDirectory, "receipt.json"), map[string]any{"state": "failed", "code": "ansible_failed", "exit_code": 2, "execution_generation": fence.Generation}); err != nil {
		t.Fatal(err)
	}
	receipt, _ := os.ReadFile(filepath.Join(fence.JobDirectory, "receipt.json"))
	if err := writeJSON(filepath.Join(fence.JobDirectory, "execution-completion.json"), map[string]any{"fence": fence, "outcome": "failed", "local_cleanup": true, "receipt_sha256": executionHash(receipt), "terminal_sha256": executionHash(terminal)}); err != nil {
		t.Fatal(err)
	}
	if err := completeContainedExecution(*fence, proof.Unit, errors.New("exit status 2"), func(string) error { return nil }); err == nil {
		t.Fatal("lost rc2")
	}
	if err := ReconcileExecutionFence(*fence); err != nil {
		t.Fatal(err)
	}
	mockContainmentObservation(t, func(string) (map[string]string, error) { t.Fatal("status attempted live observation"); return nil, nil })
	if response := readProjectedFixture(t, fence.JobDirectory); response.State != "failed" || response.Code != "ansible_failed" {
		t.Fatal(response)
	}
}
func TestControllerTerminalLegacyAndReadOnlyCompatibility(t *testing.T) {
	for _, operation := range []string{"configure-exit", "inspect-upgrade"} {
		t.Run(operation, func(t *testing.T) {
			root, job := executionFixture(t)
			if err := os.Mkdir(job, 0700); err != nil {
				t.Fatal(err)
			}
			if err := writeJSON(filepath.Join(job, "job.json"), map[string]any{"operation": operation}); err != nil {
				t.Fatal(err)
			}
			if err := writeJSON(filepath.Join(job, "receipt.json"), map[string]any{"state": "succeeded", "result": map[string]any{"cert_pin": "legacy-pin"}}); err != nil {
				t.Fatal(err)
			}
			if response := readProjectedFixture(t, job); response.State != "succeeded" || response.Result.CertPin != "legacy-pin" {
				t.Fatal(response)
			}
			if _, err := os.Stat(filepath.Join(root, "execution-admission.lock")); !os.IsNotExist(err) {
				t.Fatal("status created admission state", err)
			}
			for _, marker := range []string{"execution-dispatch-a.json", "execution-completion.json", "execution-containment.json", "execution-drain-a.json"} {
				path := filepath.Join(job, marker)
				if err := writePrivate(path, []byte("{}")); err != nil {
					t.Fatal(err)
				}
				assertUncertainProjection(t, readProjectedFixture(t, job))
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
func TestControllerTerminalErasedGenerationCannotMasqueradeLegacy(t *testing.T) {
	fence, _ := containmentCompletionFixture(t)
	if err := os.WriteFile(filepath.Join(fence.JobDirectory, "receipt.json"), []byte(`{"state":"succeeded","result":{"cert_pin":"must-not-leak"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	assertUncertainProjection(t, readProjectedFixture(t, fence.JobDirectory))
}

func publishWorkerFixtureContainment(t *testing.T, directory string) {
	t.Helper()
	raw, err := readRetryPrivate(filepath.Join(directory, "execution-completion.json"))
	if err != nil {
		t.Fatal(err)
	}
	var complete struct {
		Fence ExecutionFence `json:"fence"`
	}
	if err = json.Unmarshal(raw, &complete); err != nil {
		t.Fatal(err)
	}
	proof := containmentProof{
		Schema:       1,
		Fence:        complete.Fence,
		Mode:         "transient",
		Unit:         "ultra-execution-" + complete.Fence.Generation + ".service",
		InvocationID: strings.Repeat("a", 32),
	}
	proof.Chain = []containmentProcess{
		{
			PID:              123,
			Parent:           1,
			Starttime:        "99",
			Group:            "/system.slice/" + proof.Unit,
			ExecutableSHA256: strings.Repeat("a", 64),
			ArgvSHA256:       strings.Repeat("b", 64),
		},
	}
	if err = writeJSON(filepath.Join(directory, "execution-containment.json"), proof); err != nil {
		t.Fatal(err)
	}
	if err = persistVerifiedContainment(proof); err != nil {
		t.Fatal(err)
	}
}
func TestControllerRPCDoesNotExposeUnverifiedSuccessfulResult(t *testing.T) {
	root, _ := executionFixture(t)
	id := "11111111-2222-3333-4444-555555555555"
	directory := filepath.Join(root, id)
	prepareExecutionFixture(t, directory)
	fence, err := beginExecution(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeJSON(filepath.Join(directory, "receipt.json"), map[string]any{"state": "succeeded", "execution_generation": fence.Generation, "result": map[string]any{"cert_pin": "unsafe-result"}}); err != nil {
		t.Fatal(err)
	}
	gate, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	socket := filepath.Join(root, "status.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close() //nolint:errcheck
	done := make(chan error, 1)
	go func() {
		conn, e := listener.AcceptUnix()
		if e != nil {
			done <- e
			return
		}
		defer conn.Close() //nolint:errcheck
		response := handleConnection(conn, root, uint32(os.Geteuid()), gate)
		raw, e := json.Marshal(response)
		if e == nil {
			e = sendRequest(conn, append(raw, '\n'), nil)
		}
		done <- e
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := (Client{Socket: socket}).exchange(ctx, Message{Action: "status", ID: id})
	if err != nil {
		t.Fatalf("nonterminal job observation failed: %v", err)
	}
	assertUncertainProjection(t, response)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestClientObservesCleanupThenTerminalWithoutRedispatch(t *testing.T) {
	fence, proof := containmentCompletionFixture(t)
	// The real projection initially hides raw success despite a task result.
	receiptPath := filepath.Join(fence.JobDirectory, "receipt.json")
	raw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt map[string]any
	if err = json.Unmarshal(raw, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt["result"] = map[string]any{"cert_pin": "verified-result"}
	raw, err = json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(receiptPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	completionPath := filepath.Join(fence.JobDirectory, "execution-completion.json")
	completionRaw, err := os.ReadFile(completionPath)
	if err != nil {
		t.Fatal(err)
	}
	var completion map[string]any
	if err = json.Unmarshal(completionRaw, &completion); err != nil {
		t.Fatal(err)
	}
	completion["receipt_sha256"] = executionHash(raw)
	completionRaw, err = json.Marshal(completion)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(completionPath, completionRaw, 0600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "consumer.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close() //nolint:errcheck
	done := make(chan error, 1)
	go func() {
		for i, want := range []string{"status", "submit", "status"} {
			conn, e := listener.AcceptUnix()
			if e != nil {
				done <- e
				return
			}
			data, inputs, e := receiveRequest(conn)
			closeInputs(inputs)
			var message Message
			if e == nil {
				e = json.Unmarshal(data, &message)
			}
			if e == nil && message.Action != want {
				e = fmt.Errorf("request %d action=%s, want %s (no redispatch)", i, message.Action, want)
			}
			if e == nil {
				receiptRaw, readErr := os.ReadFile(receiptPath)
				e = readErr
				var saved Receipt
				if e == nil {
					e = json.Unmarshal(receiptRaw, &saved)
				}
				if e == nil {
					response := projectControllerReceipt(fence.JobDirectory, receiptRaw, saved)
					var encoded []byte
					encoded, e = json.Marshal(response)
					if e == nil {
						e = sendRequest(conn, append(encoded, '\n'), nil)
					}
				}
			}
			_ = conn.Close()
			if e != nil {
				done <- e
				return
			}
			if i == 1 {
				// Cleanup becomes provable only AFTER ConfigureExit saw running. No new
				// dispatch is permitted: its next request must be status of this same job.
				if e = completeContainedExecution(*fence, proof.Unit, nil, func(string) error { return nil }); e == nil {
					e = ReconcileExecutionFence(*fence)
				}
				if e != nil {
					done <- e
					return
				}
			}
		}
		done <- nil
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := Client{Socket: socket}
	terminal, err := client.ConfigurationTerminal(ctx, "11111111-2222-3333-4444-555555555555")
	if err != nil || terminal {
		t.Fatalf("pending cleanup terminal=%v err=%v", terminal, err)
	}
	binary, request := fixture(t)
	result, err := client.ConfigureExit(ctx, "11111111-2222-3333-4444-555555555555", binary, request)
	if err != nil || result.CertPin != "verified-result" {
		t.Fatalf("cleanup progress failed: result=%+v err=%v", result, err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
}

func TestClientCleanupObservationScopeAndDescriptors(t *testing.T) {
	for _, test := range []struct {
		name, action, state, code string
		descriptor, wantError     bool
	}{
		{"job-observation", "status", "running", "execution_uncertain_reconciliation_required", false, false},
		{"ready-not-job", "ready", "running", "execution_uncertain_reconciliation_required", false, true},
		{"lease-not-job", "lease-observe", "running", "execution_uncertain_reconciliation_required", false, true},
		{"terminal-not-pending", "status", "failed", "execution_uncertain_reconciliation_required", false, true},
		{"other-error", "status", "running", "ansible_failed", false, true},
		{"unexpected-fd", "status", "running", "execution_uncertain_reconciliation_required", true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "scope.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close() //nolint:errcheck
			var outputs []*os.File
			if test.descriptor {
				file, e := os.CreateTemp(t.TempDir(), "unexpected-fd")
				if e != nil {
					t.Fatal(e)
				}
				defer file.Close() //nolint:errcheck
				outputs = []*os.File{file}
			}
			done := make(chan error, 1)
			go func() {
				conn, e := listener.AcceptUnix()
				if e != nil {
					done <- e
					return
				}
				defer conn.Close() //nolint:errcheck
				_, inputs, e := receiveRequest(conn)
				closeInputs(inputs)
				if e == nil {
					var raw []byte
					raw, e = json.Marshal(Response{State: test.state, Code: test.code})
					if e == nil {
						e = sendRequest(conn, append(raw, '\n'), outputs)
					}
				}
				done <- e
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err = (Client{Socket: socket}).exchange(ctx, Message{Action: test.action})
			if (err != nil) != test.wantError {
				t.Fatalf("error=%v, wantError=%v", err, test.wantError)
			}
			if err = <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func startControllerObservationFixture(t *testing.T, state string) Client {
	t.Helper()
	gate, err := openLifecycleGate(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.close)
	socket := filepath.Join(t.TempDir(), "observation.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, e := listener.AcceptUnix()
			if e != nil {
				return
			}
			response := handleConnection(conn, state, uint32(os.Geteuid()), gate)
			raw, e := json.Marshal(response)
			if e == nil {
				e = sendRequest(conn, append(raw, '\n'), nil)
			}
			_ = conn.Close()
			if e != nil {
				t.Errorf("fixture RPC reply: %v", e)
				return
			}
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return Client{Socket: socket}
}
func preparedControllerReceiptFixture(t *testing.T) (string, string, string, ExitRequest, *ExecutionFence) {
	t.Helper()
	root, _ := executionFixture(t)
	id := "11111111-2222-3333-4444-555555555555"
	directory := filepath.Join(root, id)
	binary, request := fixture(t)
	if err := Prepare(directory, binary, request); err != nil {
		t.Fatal(err)
	}
	fence, err := beginExecution(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeJSON(filepath.Join(directory, "execution-dispatch-"+fence.Generation+".json"), fence); err != nil {
		t.Fatal(err)
	}
	var job map[string]any
	jobRaw, err := os.ReadFile(filepath.Join(directory, "job.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(jobRaw, &job); err != nil {
		t.Fatal(err)
	}
	receipt := map[string]any{
		"state":                "succeeded",
		"execution_generation": fence.Generation,
		"request_sha256":       job["request_sha256"],
		"binary_sha256":        job["binary_sha256"],
		"result":               map[string]any{"cert_pin": "verified-pin"},
	}
	if err = writeJSON(filepath.Join(directory, "receipt.json"), receipt); err != nil {
		t.Fatal(err)
	}
	return root, id, binary, request, fence
}
func completePreparedControllerFixture(t *testing.T, fence *ExecutionFence) {
	t.Helper()
	directory := fence.JobDirectory
	raw, err := os.ReadFile(filepath.Join(directory, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = writeJSON(filepath.Join(directory, "execution-completion.json"), map[string]any{"fence": fence, "local_cleanup": true, "outcome": "succeeded", "receipt_sha256": executionHash(raw)}); err != nil {
		t.Fatal(err)
	}
	publishWorkerFixtureContainment(t, directory)
	if err = ReconcileExecutionFence(*fence); err != nil {
		t.Fatal(err)
	}
}
func TestExistingPreparedSubmitObservesFencedCleanupWithoutDispatch(t *testing.T) {
	root, id, binary, request, fence := preparedControllerReceiptFixture(t)
	client := startControllerObservationFixture(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := client.exchange(ctx, Message{Action: "submit", ID: id, Binary: binary, Request: &request})
	if err != nil {
		t.Fatal(err)
	}
	assertUncertainProjection(t, response)
	terminal, err := client.ConfigurationTerminal(ctx, id)
	if err != nil || terminal {
		t.Fatalf("pending cleanup terminal=%v err=%v", terminal, err)
	}
	changed := request
	changed.Host = "192.0.2.99"
	response, err = client.exchange(ctx, Message{Action: "submit", ID: id, Binary: binary, Request: &changed})
	if err == nil || response.Code != "operation_conflict" {
		t.Fatalf("changed request accepted: %+v %v", response, err)
	}
	otherBinary := filepath.Join(t.TempDir(), "different-relay")
	if err = os.WriteFile(otherBinary, []byte("changed binary"), 0600); err != nil {
		t.Fatal(err)
	}
	response, err = client.exchange(ctx, Message{Action: "submit", ID: id, Binary: otherBinary, Request: &request})
	if err == nil || response.Code != "operation_conflict" {
		t.Fatalf("changed binary accepted: %+v %v", response, err)
	}
	// Moving admission must not permit a new job or deletion/recreation of a
	// partial stage while the original generation still owns the fleet fence.
	newID := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	response, err = client.exchange(ctx, Message{Action: "submit", ID: newID, Binary: binary, Request: &request})
	if err == nil || response.Code != "execution_uncertain_reconciliation_required" {
		t.Fatalf("new job crossed fence: %+v %v", response, err)
	}
	partial := filepath.Join(root, newID)
	if _, e := os.Lstat(partial); !os.IsNotExist(e) {
		t.Fatalf("fenced submit created directory: %v", e)
	}
	if e := os.Mkdir(partial, 0700); e != nil {
		t.Fatal(e)
	}
	marker := filepath.Join(partial, "keep-partial-stage")
	if e := writePrivate(marker, []byte("owned partial input")); e != nil {
		t.Fatal(e)
	}
	response, err = client.exchange(ctx, Message{Action: "submit", ID: newID, Binary: binary, Request: &request})
	if err == nil || response.Code != "execution_uncertain_reconciliation_required" {
		t.Fatalf("partial stage crossed fence: %+v %v", response, err)
	}
	if _, e := os.Stat(marker); e != nil {
		t.Fatalf("fenced submit removed partial stage: %v", e)
	}
	completePreparedControllerFixture(t, fence)
	result, err := client.ConfigureExit(ctx, id, binary, request)
	if err != nil || result.CertPin != "verified-pin" {
		t.Fatalf("reconnect did not observe terminal: %+v %v", result, err)
	}
	claims, err := filepath.Glob(filepath.Join(fence.JobDirectory, "execution-dispatch-*.json"))
	if err != nil || len(claims) != 1 {
		t.Fatalf("reconnect dispatched again: %v %v", claims, err)
	}
}
func TestControllerHistoricalStatusSurvivesActualPayloadRetention(t *testing.T) {
	root, id, _, _, fence := preparedControllerReceiptFixture(t)
	completePreparedControllerFixture(t, fence)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip(err)
	}
	source, err := filepath.Abs("../../deploy/ansible/library/ultra_release_retention.py")
	if err != nil {
		t.Fatal(err)
	}
	script := `import importlib.util,pathlib,shutil,sys
source,root,payload=sys.argv[1:]
spec=importlib.util.spec_from_file_location('retention_fixture',source)
r=importlib.util.module_from_spec(spec);spec.loader.exec_module(r)
removals=r.terminal_bundles(pathlib.Path(root),[])
assert payload in removals,removals
for value in removals:
 path=pathlib.Path(value)
 if path.is_dir():shutil.rmtree(path)
 else:path.unlink()
`
	if output, e := exec.Command(python, "-B", "-c", script, source, root, filepath.Join(fence.JobDirectory, "bundle")).CombinedOutput(); e != nil {
		t.Fatalf("actual retention failed: %v %s", e, output)
	}
	if _, err = os.Lstat(filepath.Join(fence.JobDirectory, "bundle")); !os.IsNotExist(err) {
		t.Fatal("collector retained payload", err)
	}
	if validateExecutionTerminal(*fence) == nil {
		t.Fatal("live validation accepted collected payload")
	}
	client := startControllerObservationFixture(t, root)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := client.exchange(ctx, Message{Action: "status", ID: id})
	if err != nil || response.State != "succeeded" || response.Result.CertPin != "verified-pin" {
		t.Fatalf("historical RPC lost success: %+v %v", response, err)
	}
	terminal, err := client.ConfigurationTerminal(ctx, id)
	if err != nil || !terminal {
		t.Fatalf("collected job is not terminal: %v %v", terminal, err)
	}
	ownershipPath := filepath.Join(fence.JobDirectory, "bundle.retention.json")
	ownership, e := os.ReadFile(ownershipPath)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(ownershipPath); e != nil {
		t.Fatal(e)
	}
	response, e = client.exchange(ctx, Message{Action: "status", ID: id})
	if e != nil {
		t.Fatal(e)
	}
	assertUncertainProjection(t, response)
	if e = os.WriteFile(ownershipPath, ownership, 0600); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{"job.json", "request.json", "bundle.retention.json", "execution-completion.json", "execution-drain-" + fence.Generation + ".json"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(fence.JobDirectory, name)
			original, e := os.ReadFile(path)
			if e != nil {
				t.Fatal(e)
			}
			// Protected metadata bytes are bound to immutable completion/drain evidence.
			changed := append(append([]byte{}, original...), byte(' '))
			if strings.HasPrefix(name, "execution-drain-") {
				var metadata map[string]any
				if e = json.Unmarshal(original, &metadata); e != nil {
					t.Fatal(e)
				}
				metadata["completion_sha256"] = strings.Repeat("f", 64)
				changed, e = json.Marshal(metadata)
				if e != nil {
					t.Fatal(e)
				}
			}
			if name == "bundle.retention.json" {
				var metadata map[string]any
				if e = json.Unmarshal(original, &metadata); e != nil {
					t.Fatal(e)
				}
				metadata["identity"] = map[string]string{"request_sha256": strings.Repeat("f", 64)}
				changed, e = json.Marshal(metadata)
				if e != nil {
					t.Fatal(e)
				}
			}
			if e = os.WriteFile(path, changed, 0600); e != nil {
				t.Fatal(e)
			}
			t.Cleanup(func() {
				if e := os.WriteFile(path, original, 0600); e != nil {
					t.Error(e)
				}
			})
			response, e := client.exchange(ctx, Message{Action: "status", ID: id})
			if e != nil {
				t.Fatal(e)
			}
			assertUncertainProjection(t, response)
		})
	}
}
