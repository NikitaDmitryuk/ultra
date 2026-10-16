//go:build linux

package deployansible

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestActiveLifecycleAttachmentRequiresBrokerAuthorization(t *testing.T) {
	const id = "11111111-2222-3333-4444-555555555555"
	const other = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	for _, state := range []string{"applying", "checking", "retired", "released", "mismatched"} {
		t.Run(state, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			gate, err := openLifecycleGate(root)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.close()
			if result := gate.transition(id, "applying"); result.Code != "" {
				t.Fatal(result)
			}
			wantCode := ""
			switch state {
			case "checking", "released":
				if result := gate.transition(id, state); result.Code != "" {
					t.Fatal(result)
				}
				if state == "released" {
					wantCode = "lifecycle_not_owned"
				}
			case "retired":
				if result := gate.retire(id); result.Code != "" {
					t.Fatal(result)
				}
				wantCode = "lifecycle_retired"
			case "mismatched":
				if result := gate.transition(id, "released"); result.Code != "" {
					t.Fatal(result)
				}
				if result := gate.transition(other, "applying"); result.Code != "" {
					t.Fatal(result)
				}
				if result := gate.transition(other, "checking"); result.Code != "" {
					t.Fatal(result)
				}
				wantCode = "lifecycle_not_owned"
			}
			// Every case except applying has a free flock. It must not bypass the
			// controller's UUID fence, including the durable fence after restart.
			if state == "retired" {
				gate.close()
				gate, err = openLifecycleGate(root)
				if err != nil {
					t.Fatal(err)
				}
				defer gate.close()
			}
			if state != "applying" {
				_, release, lockErr := WithOperationLock(context.Background(), root)
				if lockErr != nil {
					t.Fatal("fixture flock was not free", lockErr)
				}
				release()
			}
			socket := filepath.Join(root, "controller.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close() //nolint:errcheck
			done := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptUnix()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close() //nolint:errcheck
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				data, inputs, err := receiveRequest(conn)
				defer closeInputs(inputs)
				if err != nil {
					done <- err
					return
				}
				var message Message
				if err = json.NewDecoder(bytes.NewReader(data)).Decode(&message); err != nil {
					done <- err
					return
				}
				if message.Action != "lease-attach" || message.ID != id {
					done <- fmt.Errorf("unexpected attachment: %+v", message)
					return
				}
				response := gate.attach(message.ID)
				defer closeInputs(response.leaseOutputs)
				data, err = json.Marshal(response)
				if err == nil {
					err = sendRequest(conn, append(data, '\n'), response.leaseOutputs)
				}
				done <- err
			}()
			ctx, release, err := (Client{Socket: socket}).WithActiveLifecycleOperationLock(context.Background(), root, id)
			if serverErr := <-done; serverErr != nil {
				t.Fatal(serverErr)
			}
			called := false
			if err == nil {
				defer release()
				// This is the execution boundary used by frozen retry callers.
				called = true
				if lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease); !ok || lease.directory != root || !lease.active.Load() {
					t.Fatal("missing active operation lease")
				}
			}
			if wantCode != "" {
				if err == nil || !strings.Contains(err.Error(), wantCode) || called || release != nil {
					t.Fatalf("rejected lifecycle reached execution: called=%v err=%v", called, err)
				}
			} else if err != nil || !called || gate.current.ID != id || gate.current.Phase != "applying" {
				t.Fatalf("active lifecycle did not attach: called=%v err=%v", called, err)
			}
		})
	}
}

func TestActiveLifecycleAttachmentDoesNotFallbackWithoutBroker(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	client := Client{Socket: filepath.Join(root, "absent.sock")}
	const id = "11111111-2222-3333-4444-555555555555"
	if _, release, err := client.WithActiveLifecycleOperationLock(context.Background(), root, id); err == nil || release != nil {
		t.Fatal("missing broker accepted", err)
	}
	if _, release, err := client.WithActiveLifecycleOperationLock(context.Background(), root, "invalid"); err == nil || err.Error() != "invalid operation id" || release != nil {
		t.Fatal("invalid UUID error lost", err)
	}
	_, release, err := client.WithLifecycleOperationLock(context.Background(), root, id)
	if err != nil {
		t.Fatal("ordinary free local lock now requires broker", err)
	}
	release()
}

func TestActiveLifecycleAttachmentRejectsUnconfirmedResponses(t *testing.T) {
	for _, fault := range []string{"released", "missing-descriptor", "unsupported"} {
		t.Run(fault, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			held, unlock, err := WithOperationLock(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			defer unlock()
			socket := filepath.Join(root, "controller.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close() //nolint:errcheck
			done := make(chan error, 1)
			go func() {
				conn, err := listener.AcceptUnix()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close() //nolint:errcheck
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_, inputs, err := receiveRequest(conn)
				closeInputs(inputs)
				if err != nil {
					done <- err
					return
				}
				response := Response{State: "applying"}
				outputs := []*os.File{held.Value(operationLeaseKey{}).(*operationLease).file}
				switch fault {
				case "released":
					response.State = "released"
				case "missing-descriptor":
					outputs = nil
				case "unsupported":
					response.Code = "unsupported_action"
					outputs = nil
				}
				data, err := json.Marshal(response)
				if err == nil {
					err = sendRequest(conn, append(data, '\n'), outputs)
				}
				done <- err
			}()
			_, release, err := (Client{Socket: socket}).WithActiveLifecycleOperationLock(context.Background(), root, "11111111-2222-3333-4444-555555555555")
			if err == nil || release != nil {
				t.Fatal("unconfirmed attachment accepted", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			unlock()
			// A rejected descriptor must be closed, including invalid success states.
			_, release, err = WithOperationLock(context.Background(), root)
			if err != nil {
				t.Fatal("rejected response leaked descriptor", err)
			}
			release()
		})
	}
}
