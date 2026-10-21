//go:build linux

package deployansible

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadyReturnsTypedSafeFailure(t *testing.T) {
	for _, code := range []string{"lifecycle_busy", "private-response-token"} {
		t.Run(code, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "worker.sock")
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
				_, inputs, err := receiveRequest(conn)
				closeInputs(inputs)
				if err == nil {
					raw, marshalErr := json.Marshal(Response{Code: code, Diagnostic: Diagnostic{Stage: "private-stage-token"}})
					err = marshalErr
					if err == nil {
						err = sendRequest(conn, append(raw, '\n'), nil)
					}
				}
				done <- err
			}()
			err = (Client{Socket: socket}).Ready(context.Background())
			var readiness *ReadinessError
			want := "controller_unavailable"
			if code == "lifecycle_busy" {
				want = code
			}
			if !errors.As(err, &readiness) || readiness.ReadinessCode() != want || strings.Contains(err.Error(), "private") {
				t.Fatalf("unsafe readiness error: %v", err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
	t.Run("transport", func(t *testing.T) {
		err := (Client{Socket: filepath.Join(t.TempDir(), "private-socket")}).Ready(context.Background())
		var readiness *ReadinessError
		if !errors.As(err, &readiness) || readiness.ReadinessCode() != "controller_unavailable" || err.Error() != "controller_unavailable" {
			t.Fatalf("transport readiness error: %v", err)
		}
	})
}
