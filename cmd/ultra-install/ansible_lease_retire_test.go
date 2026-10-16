package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func TestAnsibleLeaseRetireRejectsInvalidArguments(t *testing.T) {
	const id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"missing id", nil, "exact canonical lifecycle UUID"},
		{"invalid id", []string{"--id", "../bad"}, "exact canonical lifecycle UUID"},
		{"uppercase id", []string{"--id", strings.ToUpper(id)}, "exact canonical lifecycle UUID"},
		{"compact id", []string{"--id", strings.ReplaceAll(id, "-", "")}, "exact canonical lifecycle UUID"},
		{"urn id", []string{"--id", "urn:uuid:" + id}, "exact canonical lifecycle UUID"},
		{"phase", []string{"--id", id, "--phase", "released"}, "cannot be combined"},
		{"empty phase", []string{"--id", id, "--phase="}, "cannot be combined"},
		{"resume", []string{"--id", id, "--resume-frozen"}, "cannot be combined"},
		{"false resume", []string{"--id", id, "--resume-frozen=false"}, "cannot be combined"},
		{"positional", []string{"--id", id, "extra"}, "positional arguments"},
		{"separator positional", []string{"--id", id, "--", "extra"}, "positional arguments"},
		{"unknown flag", []string{"--id", id, "--unknown"}, "flag provided but not defined"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// An invalid socket proves validation fails before contacting a daemon.
			args := append([]string{"--socket", "relative.sock", "--retire"}, tc.args...)
			err := runAnsibleLeaseCommand(context.Background(), args, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAnsibleLeaseRetireDispatchAndFailClosed(t *testing.T) {
	const id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	for _, tc := range []struct {
		name     string
		response string
		wantErr  string
	}{
		{"released", `{"state":"released"}`, ""},
		{"unsupported", `{"code":"unknown_action"}`, "unknown_action"},
		{"external lock", `{"code":"infrastructure_busy"}`, "infrastructure_busy"},
		{"empty state", `{}`, "invalid lifecycle retirement state"},
		{"wrong state", `{"state":"applying"}`, "invalid lifecycle retirement state"},
		{"malformed", `broken`, "ansible response unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Keep the path below the Unix socket limit even with a long GOTMPDIR.
			directory, err := os.MkdirTemp("/tmp", "ultra-lease-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.RemoveAll(directory); err != nil {
					t.Error(err)
				}
			})
			socket := filepath.Join(directory, "controller.sock")
			listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close() //nolint:errcheck
			if err := listener.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			type result struct {
				message deployansible.Message
				err     error
			}
			done := make(chan result, 1)
			go func() {
				conn, acceptErr := listener.AcceptUnix()
				if acceptErr != nil {
					done <- result{err: acceptErr}
					return
				}
				defer conn.Close() //nolint:errcheck
				if deadlineErr := conn.SetDeadline(time.Now().Add(5 * time.Second)); deadlineErr != nil {
					done <- result{err: deadlineErr}
					return
				}
				var message deployansible.Message
				if decodeErr := json.NewDecoder(conn).Decode(&message); decodeErr != nil {
					done <- result{err: decodeErr}
					return
				}
				_, writeErr := io.WriteString(conn, tc.response+"\n")
				done <- result{message: message, err: writeErr}
			}()
			var output bytes.Buffer
			err = runAnsibleLeaseCommand(context.Background(), []string{"--socket", socket, "--retire", "--id", id}, &output)
			if tc.wantErr == "" {
				if err != nil || output.String() != "Ansible lifecycle retired: "+id+"\n" {
					t.Fatalf("error = %v, output = %q", err, output.String())
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) || output.Len() != 0 {
				t.Fatalf("error = %v, output = %q, want %q", err, output.String(), tc.wantErr)
			}
			got := <-done
			if got.err != nil {
				t.Fatal(got.err)
			}
			if got.message.Action != "lease-retire" || got.message.ID != id || got.message.NextID != "" ||
				got.message.Binary != "" || got.message.Request != nil || got.message.NodeID != "" {
				t.Fatalf("unexpected retirement request: %+v", got.message)
			}
		})
	}
}
