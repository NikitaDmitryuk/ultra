//go:build linux

package deployansible

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

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
					if result.Code != "" || (action == "lease-retire" && (result.State != "released" || gate.blocked())) || (action == "lease-supersede" && (result.State != "applying" || !gate.blocked())) {
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
