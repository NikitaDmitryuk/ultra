//go:build linux

package deployansible

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestLifecycleAttachmentTransfersBrokerDescriptor(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	gate, err := openLifecycleGate(root)
	if err != nil {
		t.Fatal(err)
	}
	defer gate.close()
	id := "11111111-2222-3333-4444-555555555555"
	if response := gate.transition(id, "applying"); response.Code != "" {
		t.Fatal(response)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	stage := filepath.Join(root, "bootstrap-stage")
	request, _ := json.Marshal(map[string]any{"inventory": map[string]any{}, "variables": map[string]any{"ultra_lock_directory": root}})
	digest := sha256.Sum256(request)
	if err = prepareLocalOperation(stage, "bootstrap", request, hex.EncodeToString(digest[:]), Export); err != nil {
		t.Fatal(err)
	}
	jobRaw, err := os.ReadFile(filepath.Join(stage, "job.json"))
	if err != nil {
		t.Fatal(err)
	}
	var failed map[string]any
	if err = json.Unmarshal(jobRaw, &failed); err != nil {
		t.Fatal(err)
	}
	failed["state"] = "failed"
	failed["code"] = "original_timeout"
	failedRaw, _ := json.Marshal(failed)
	if err = writePrivate(filepath.Join(stage, "receipt.json"), failedRaw); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(root, "ansible-playbook")
	source := "#!" + python + "\n" + `import pathlib,sys
job=pathlib.Path(sys.argv[-1][1:]).parent
result=job/'result.json'
result.write_text('{"verified":true}')
result.chmod(0o600)
`
	if err = os.WriteFile(executable, []byte(source), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = RetryFrozenBootstrapWithLock(context.Background(), stage, python, executable); err == nil {
		t.Fatal("independent retry acquired broker-retained lease")
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
		response := gate.attach(message.ID)
		defer closeInputs(response.leaseOutputs)
		data, err = json.Marshal(response)
		if err == nil {
			err = sendRequest(conn, append(data, '\n'), response.leaseOutputs)
		}
		done <- err
	}()
	ctx, release, err := (Client{Socket: socket}).WithLifecycleOperationLock(context.Background(), root, id)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, err = RetryFrozenBootstrap(ctx, stage, python, executable); err != nil {
		t.Fatal("frozen bootstrap retry did not reuse broker attachment", err)
	}
	if _, err = os.Stat(filepath.Join(stage, "history", "attempt-1.json")); err != nil {
		t.Fatal("failed bootstrap receipt not preserved", err)
	}
	requireCloseOnExec(t, ctx.Value(operationLeaseKey{}).(*operationLease).file)
	if ctx.Value(operationLeaseKey{}) == nil {
		t.Fatal("received descriptor not imported into operation context")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	gate.close()
	if _, unlock, err := WithOperationLock(context.Background(), root); err == nil {
		unlock()
		t.Fatal("broker shutdown unlocked surviving attached caller")
	}
	release()
	_, unlock, err := WithOperationLock(context.Background(), root)
	if err != nil {
		t.Fatal("all descriptors closed but lock retained", err)
	}
	unlock()
}
