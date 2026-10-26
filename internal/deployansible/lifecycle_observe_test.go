//go:build linux

package deployansible

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLifecycleObservationNeverAcquiresOrPromotes(t *testing.T) {
	const id = "11111111-2222-3333-4444-555555555555"
	for _, phase := range []string{"applying", "checking", "checking-held", "released", "foreign", "retired"} {
		t.Run(phase, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			gate, err := openLifecycleGate(root)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.close()
			if response := gate.transition(id, "applying"); response.Code != "" {
				t.Fatal(response)
			}
			switch phase {
			case "checking", "released":
				if response := gate.transition(id, phase); response.Code != "" {
					t.Fatal(response)
				}
			case "checking-held":
				if err = gate.save(lifecycleState{ID: id, Phase: "checking"}); err != nil {
					t.Fatal(err)
				}
			case "foreign":
				if err = gate.save(lifecycleState{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", Phase: "applying"}); err != nil {
					t.Fatal(err)
				}
			case "retired":
				if response := gate.retire(id); response.Code != "" {
					t.Fatal(response)
				}
			}
			before, _ := os.ReadFile(filepath.Join(root, "lifecycle.json"))
			lock := gate.lock
			current := gate.current
			response := gate.observe(id)
			after, _ := os.ReadFile(filepath.Join(root, "lifecycle.json"))
			if !bytes.Equal(before, after) || gate.lock != lock || gate.current != current {
				t.Fatal("observation mutated reservation")
			}
			success := phase == "applying" || phase == "checking-held"
			if success != (response.Code == "") || (success && len(response.leaseOutputs) != 1) {
				t.Fatalf("unexpected observation: %+v", response)
			}
			closeInputs(response.leaseOutputs)
			if lock == nil {
				_, release, lockErr := WithOperationLock(context.Background(), root)
				if lockErr != nil {
					t.Fatal("observation acquired previously free infrastructure lock", lockErr)
				}
				release()
			}
		})
	}
}

func TestLifecycleObservationClientValidatesAndClosesDescriptor(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		name := "untrusted"
		if trusted {
			name = "trusted"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			gate, err := openLifecycleGate(root)
			if err != nil {
				t.Fatal(err)
			}
			defer gate.close()
			const id = "11111111-2222-3333-4444-555555555555"
			if response := gate.transition(id, "applying"); response.Code != "" {
				t.Fatal(response)
			}
			socket := filepath.Join(root, "controller.sock")
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
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				raw, inputs, e := receiveRequest(conn)
				defer closeInputs(inputs)
				if e != nil {
					done <- e
					return
				}
				var message Message
				if e = json.Unmarshal(raw, &message); e != nil {
					done <- e
					return
				}
				if message.Action != "lease-observe" || message.ID != id {
					done <- os.ErrInvalid
					return
				}
				response := gate.observe(id)
				if !trusted {
					closeInputs(response.leaseOutputs)
					unrelated, openErr := os.CreateTemp(root, "untrusted-")
					if openErr != nil {
						done <- openErr
						return
					}
					response.leaseOutputs = []*os.File{unrelated}
				}
				defer closeInputs(response.leaseOutputs)
				raw, e = json.Marshal(response)
				if e == nil {
					e = sendRequest(conn, append(raw, '\n'), response.leaseOutputs)
				}
				done <- e
			}()
			err = (Client{Socket: socket}).ObserveLifecycleOperationLock(context.Background(), root, id)
			if e := <-done; e != nil {
				t.Fatal(e)
			}
			if trusted != (err == nil) {
				t.Fatalf("descriptor trust mismatch: %v", err)
			}
			if gate.current.Phase != "applying" {
				t.Fatal("observation changed phase")
			}
			if response := gate.transition(id, "released"); response.Code != "" {
				t.Fatal(response)
			}
			_, release, lockErr := WithOperationLock(context.Background(), root)
			if lockErr != nil {
				t.Fatal("observer leaked locked descriptor", lockErr)
			}
			release()
		})
	}
}
