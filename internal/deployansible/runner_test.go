package deployansible

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/config"
)

func fixture(t *testing.T) (string, ExitRequest) {
	t.Helper()
	root := t.TempDir()
	pins := filepath.Join(root, "known hosts")
	if err := os.WriteFile(pins, []byte("192.0.2.2 ssh-ed25519 fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "identity"), []byte("test-private-key"), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "relay")
	if err := os.WriteFile(binary, []byte("pinned-test-binary"), 0600); err != nil {
		t.Fatal(err)
	}
	return binary, ExitRequest{
		Host:       "192.0.2.2",
		User:       "root",
		Identity:   filepath.Join(root, "identity"),
		KnownHosts: pins,
		BridgeIPv4: "192.0.2.1",
		Spec: config.Spec{
			ExitCertPaths: config.CertPaths{CertFile: "/etc/ultra-relay/fullchain.pem", KeyFile: "/etc/ultra-relay/privkey.pem"},
			Role:          config.RoleExit,
			MimicPreset:   "steamlike",
			ListenAddress: "0.0.0.0",
			VLESSPort:     8443,
			Exit:          config.ExitTunnelSpec{TunnelUUID: "11111111-2222-3333-4444-555555555555"},
			SplithttpHost: "example.com",
			SplithttpPath: "/fixture",
		},
	}
}

func TestPrepareProtectsIdentityAndDoesNotOverwrite(t *testing.T) {
	binary, request := fixture(t)
	directory := filepath.Join(t.TempDir(), "job")
	if err := Prepare(directory, binary, request); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"job.json", "request.json", "ultra-relay", "bundle/controller.py"} {
		info, err := os.Stat(filepath.Join(directory, name))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatalf("private input %s: %v", name, err)
		}
	}
	var saved ExitRequest
	data, _ := os.ReadFile(filepath.Join(directory, "request.json"))
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Spec.Exit.TunnelUUID != request.Spec.Exit.TunnelUUID {
		t.Fatal("route UUID changed")
	}
	if err := Prepare(directory, binary, request); err == nil {
		t.Fatal("existing job overwritten")
	}
}

func TestPrepareRejectsMissingAndWritablePins(t *testing.T) {
	binary, request := fixture(t)
	if err := os.Chmod(request.KnownHosts, 0666); err != nil {
		t.Fatal(err)
	}
	if err := Prepare(filepath.Join(t.TempDir(), "job"), binary, request); err == nil {
		t.Fatal("writable pins accepted")
	}
	request.KnownHosts = filepath.Join(t.TempDir(), "missing")
	if err := request.Validate(); err == nil {
		t.Fatal("missing pins accepted")
	}
}

func TestSupervisorReceiptRetryAndTampering(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	binary, request := fixture(t)
	root := t.TempDir()
	directory := filepath.Join(root, "job")
	if err = Prepare(directory, binary, request); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(root, "ansible-playbook")
	source := `#!` + python + `
import json,pathlib,sys
variables=json.loads((pathlib.Path(sys.argv[-1][1:]).parent/'variables.json').read_text())
result=pathlib.Path(variables['ultra_result_file'])
result.write_text(json.dumps({'cert_pin':'a'*64}))
result.chmod(0o600)
count=result.parent/'calls'
count.write_text(str(int(count.read_text())+1 if count.exists() else 1))
`
	if err = os.WriteFile(stub, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		result, err := Execute(context.Background(), directory, python, stub)
		if err != nil || result.CertPin != strings.Repeat("a", 64) {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	calls, _ := os.ReadFile(filepath.Join(directory, "calls"))
	if string(calls) != "1" {
		t.Fatal("completed attempt ran again")
	}
	if err = os.WriteFile(filepath.Join(directory, "request.json"), []byte(`{"host":"192.0.2.99"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Execute(context.Background(), directory, python, stub); err == nil {
		t.Fatal("changed request reused success")
	}
}

func TestFailedAttemptCannotReuseStaleResult(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	binary, request := fixture(t)
	directory := filepath.Join(t.TempDir(), "job")
	if err = Prepare(directory, binary, request); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "result.json"), []byte(`{"cert_pin":"`+strings.Repeat("a", 64)+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = Execute(context.Background(), directory, python, "/bin/false"); err == nil {
			t.Fatal("failed attempt accepted stale success")
		}
	}
	if _, err = os.Stat(filepath.Join(directory, "result.json")); !os.IsNotExist(err) {
		t.Fatal("stale result retained")
	}
}

func TestInterruptedExecutionRequiresExplicitReconciliation(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	binary, request := fixture(t)
	root := t.TempDir()
	directory := filepath.Join(root, "job")
	if err = Prepare(directory, binary, request); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(root, "ansible-playbook")
	source := "#!" + python + `
import json,pathlib,sys,time
value=json.loads((pathlib.Path(sys.argv[-1][1:]).parent/'variables.json').read_text())
result=pathlib.Path(value['ultra_result_file'])
started=result.parent/'started'
if not started.exists():
    started.write_text('started')
    time.sleep(30)
result.write_text(json.dumps({'cert_pin':'c'*64}))
result.chmod(0o600)
`
	if err = os.WriteFile(stub, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := Execute(ctx, directory, python, stub); done <- err }()
	deadline := time.Now().Add(5 * time.Second)
	started := false
	for time.Now().Before(deadline) {
		if _, err = os.Stat(filepath.Join(directory, "started")); err == nil {
			started = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err = <-done; err == nil {
		t.Fatal("interrupted execution reported success")
	}
	if !started {
		t.Fatal("execution never started")
	}
	_, err = Execute(context.Background(), directory, python, stub)
	if !errors.Is(err, ErrExecutionFenced) {
		t.Fatalf("interrupted execution redispatched: %v", err)
	}
}
