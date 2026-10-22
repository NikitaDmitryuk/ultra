//go:build linux

package deployansible

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigurationTerminalAfterSubmitterTimeoutRequiresVerifiedCompletion(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	binary, request := fixture(t)
	root := t.TempDir()
	socket, state := filepath.Join(root, "worker.sock"), filepath.Join(root, "state")
	stub, release := filepath.Join(root, "ansible-playbook"), filepath.Join(root, "release")
	source := "#!" + python + "\nimport pathlib,time,sys\nwhile not pathlib.Path(" + "'" + release + "'" + ").exists(): time.sleep(0.01)\nsys.exit(1)\n"
	if err := os.WriteFile(stub, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	serviceCtx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Serve(serviceCtx, socket, state, python, stub, uint32(os.Getuid())) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	client := Client{Socket: socket}
	deadline := time.Now().Add(5 * time.Second)
	for client.Ready(context.Background()) != nil {
		if time.Now().After(deadline) {
			t.Fatal("worker unavailable")
		}
		time.Sleep(10 * time.Millisecond)
	}
	id := "11111111-2222-3333-4444-555555555555"
	caller, stop := context.WithTimeout(context.Background(), 150*time.Millisecond)
	_, err = client.ConfigureExit(caller, id, binary, request)
	stop()
	if err == nil {
		t.Fatal("blocked worker returned success")
	}
	terminal, err := client.ConfigurationTerminal(context.Background(), id)
	if err != nil || terminal {
		t.Fatalf("running/queued job considered terminal after caller timeout: %v %v", terminal, err)
	}
	if _, err := client.ConfigurationTerminal(context.Background(), "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"); err == nil {
		t.Fatal("missing receipt proved termination")
	}
	if err := os.WriteFile(release, []byte("finish"), 0600); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		raw, readErr := os.ReadFile(filepath.Join(state, id, "receipt.json"))
		var receipt Receipt
		if readErr == nil && json.Unmarshal(raw, &receipt) == nil && receipt.State == "failed" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker did not record its abnormal exit")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Exit 1 has no normal terminal callback. Even after the local process ends,
	// its failed receipt cannot prove that all remote work has stopped.
	terminal, err = client.ConfigurationTerminal(context.Background(), id)
	if err != nil || terminal {
		t.Fatalf("unverified failure considered terminal: %v %v", terminal, err)
	}
	if _, err = os.Stat(filepath.Join(state, id, "execution-completion.json")); !os.IsNotExist(err) {
		t.Fatal("abnormal exit produced completion evidence", err)
	}
	directory := filepath.Join(state, id)
	if fence, err := inspectExecutionFence(executionFenceDirectory(directory)); err != nil || fence == nil ||
		fence.JobDirectory != directory {
		t.Fatal("abnormal exit released its execution fence", fence, err)
	}
}
