package deployansible

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"time"
)

// Client submits jobs to a root-owned systemd worker. The worker survives relay restarts.
type Client struct{ Socket string }
type Message struct {
	leaseInputs []*os.File
	Action      string       `json:"action"`
	ID          string       `json:"id"`
	NextID      string       `json:"next_id,omitempty"`
	Binary      string       `json:"binary,omitempty"`
	Request     *ExitRequest `json:"request,omitempty"`
	NodeID      string       `json:"node_id,omitempty"`
}
type Response struct {
	leaseOutputs []*os.File
	Diagnostic   Diagnostic `json:"diagnostic,omitempty"`
	State        string     `json:"state"`
	Code         string     `json:"code,omitempty"`
	Result       Result     `json:"result,omitempty"`
}

func (c Client) exchange(ctx context.Context, message Message) (Response, error) {
	if !filepath.IsAbs(c.Socket) {
		return Response{}, errors.New("absolute controller socket required")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return Response{}, errors.New("ansible controller unavailable")
	}
	defer conn.Close() //nolint:errcheck
	deadline := time.Now().Add(10 * time.Second)
	if limit, ok := ctx.Deadline(); ok && limit.Before(deadline) {
		deadline = limit
	}
	if err = conn.SetDeadline(deadline); err != nil {
		return Response{}, err
	}
	unixConn, okay := conn.(*net.UnixConn)
	if !okay {
		return Response{}, errors.New("invalid controller transport")
	}
	serverUID, err := peerUID(unixConn)
	if err != nil || (serverUID != 0 && serverUID != uint32(os.Geteuid())) {
		return Response{}, errors.New("untrusted controller peer")
	}
	inputs := message.leaseInputs
	if message.Action == "submit" {
		if message.Request == nil {
			return Response{}, errors.New("exit request required")
		}
		inputs, err = openInputs(message.Binary, *message.Request)
		if err != nil {
			return Response{}, err
		}
		defer closeInputs(inputs)
	}
	data, err := json.Marshal(message)
	if err != nil || len(data) > 1<<20 {
		return Response{}, errors.New("invalid controller request")
	}
	if err = sendRequest(unixConn, append(data, '\n'), inputs); err != nil {
		return Response{}, err
	}
	data, outputs, err := receiveRequest(unixConn)
	if err != nil {
		return Response{}, errors.New("ansible response unavailable")
	}
	var response Response
	if err = json.NewDecoder(io.MultiReader(bytes.NewReader(data), conn)).Decode(&response); err != nil {
		closeInputs(outputs)
		return Response{}, errors.New("ansible response unavailable")
	}
	if response.Code != "" {
		closeInputs(outputs)
		if response.Diagnostic.Code != "" {
			return response, fmt.Errorf("%s (%s: %s; %s)", response.Code,
				response.Diagnostic.Node, response.Diagnostic.Stage, response.Diagnostic.Code)
		}
		return response, fmt.Errorf("%s (%s: %s)", response.Code, response.Diagnostic.Node, response.Diagnostic.Stage)
	}
	if (message.Action == "lease-attach" && len(outputs) != 1) || (message.Action != "lease-attach" && len(outputs) != 0) {
		closeInputs(outputs)
		return Response{}, errors.New("unexpected controller descriptors")
	}
	response.leaseOutputs = outputs
	return response, nil
}

func (c Client) Ready(ctx context.Context) error {
	_, err := c.exchange(ctx, Message{Action: "ready"})
	return err
}

func (c Client) ConfigureExit(ctx context.Context, id, binary string, request ExitRequest) (Result, error) {
	response, err := c.exchange(ctx, Message{Action: "submit", ID: id, Binary: binary, Request: &request})
	if err != nil {
		return Result{}, err
	}
	for {
		switch response.State {
		case "succeeded":
			return response.Result, nil
		case "failed":
			return Result{}, errors.New("ansible configuration failed")
		case "queued", "running":
		default:
			return Result{}, errors.New("invalid Ansible operation state")
		}
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-time.After(time.Second):
		}
		response, err = c.exchange(ctx, Message{Action: "status", ID: id})
		if err != nil {
			return Result{}, err
		}
	}
}

var jobID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

// Serve uses a single worker; a disconnected submitter cannot cancel a saved job.
// State and socket directories must already be provisioned with private ownership.
func Serve(ctx context.Context, socket, state, python, executable string, allowedUID uint32) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for _, path := range []string{socket, state, python, executable} {
		if !filepath.IsAbs(path) {
			return errors.New("absolute service paths required")
		}
	}
	for _, path := range []string{python, executable} {
		executableInfo, err := os.Stat(path)
		if err != nil || !executableInfo.Mode().IsRegular() || executableInfo.Mode().Perm()&0111 == 0 {
			return errors.New("controller runtime unavailable")
		}
	}
	if err := os.MkdirAll(state, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(state)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || !ownedByProcess(info) {
		return errors.New("private controller state required")
	}
	lock, err := controllerLock(filepath.Join(state, "controller.lock"))
	if err != nil {
		return errors.New("controller already running")
	}
	defer lock.Close() //nolint:errcheck
	if existing, statErr := os.Lstat(socket); statErr == nil {
		if existing.Mode()&os.ModeSocket == 0 {
			return errors.New("controller socket path occupied")
		}
		if err = os.Remove(socket); err != nil {
			return err
		}
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close() //nolint:errcheck
	account, err := user.LookupId(strconv.FormatUint(uint64(allowedUID), 10))
	if err != nil {
		return errors.New("controller account unavailable")
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return errors.New("controller group unavailable")
	}
	if err = os.Chown(socket, -1, gid); err != nil {
		return err
	}
	if err = os.Chmod(socket, 0660); err != nil {
		return err
	}
	gate, err := openLifecycleGate(state)
	if err != nil {
		return err
	}
	defer gate.close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = listener.Close()
		case <-done:
		}
	}()
	// The private state directory also serializes independent invocations of each job.
	// The process loop schedules only one Ansible process at a time.
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	workerDone := make(chan struct{})
	defer func() { cancel(); <-workerDone }()
	go func() {
		defer close(workerDone)
		for {
			entries, _ := os.ReadDir(state)
			for _, entry := range entries {
				if !entry.IsDir() || !jobID.MatchString(entry.Name()) {
					continue
				}
				directory := filepath.Join(state, entry.Name())
				if _, err := os.Stat(filepath.Join(directory, "prepared")); err != nil {
					continue
				}
				var receipt Receipt
				raw, readErr := os.ReadFile(filepath.Join(directory, "receipt.json"))
				if readErr == nil && json.Unmarshal(raw, &receipt) == nil && (receipt.State == "failed" || receipt.State == "succeeded") {
					continue
				}
				var job struct {
					Operation string `json:"operation"`
				}
				jobRaw, jobErr := os.ReadFile(filepath.Join(directory, "job.json"))
				if jobErr != nil || json.Unmarshal(jobRaw, &job) != nil {
					continue
				}
				operationLock, lockErr := gate.jobLock(job.Operation)
				if lockErr != nil {
					continue // Another lifecycle operation owns infrastructure; keep the job queued.
				}
				_, runErr := Execute(ctx, directory, python, executable)
				_ = operationLock.Close()
				if runErr != nil && ctx.Err() == nil {
					if _, receiptErr := os.Stat(filepath.Join(directory, "receipt.json")); os.IsNotExist(receiptErr) {
						_ = writeJSON(filepath.Join(directory, "receipt.json"), Receipt{State: "failed", Code: "job_validation_failed"})
						_ = syncDirectory(directory)
					}
				}
				if ctx.Err() != nil {
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
			}
		}
	}()
	for {
		conn, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		// Short synchronous request handling prevents concurrent duplicate submissions.
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		response := handleConnection(conn, state, allowedUID, gate)
		data, marshalErr := json.Marshal(response)
		if marshalErr == nil {
			_ = sendRequest(conn, append(data, '\n'), response.leaseOutputs)
		}
		closeInputs(response.leaseOutputs)
		_ = conn.Close()
	}
}

func handleConnection(conn *net.UnixConn, state string, allowedUID uint32, gate *lifecycleGate) Response {
	uid, err := peerUID(conn)
	if err != nil || (uid != 0 && uid != allowedUID) {
		return Response{Code: "controller_access_denied"}
	}
	var message Message
	data, inputs, err := receiveRequest(conn)
	if err != nil {
		return Response{Code: "invalid_request"}
	}
	defer closeInputs(inputs)
	decoder := json.NewDecoder(io.LimitReader(io.MultiReader(bytes.NewReader(data), conn), 1<<20))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&message); err != nil {
		return Response{Code: "invalid_request"}
	}
	if message.Action != "submit" && message.Action != "lease-applying" && message.Action != "lease-resume" &&
		message.Action != "lease-supersede" &&
		len(inputs) != 0 {
		return Response{Code: "unexpected_submitted_inputs"}
	}
	if message.Action == "lifecycle-status" {
		return Response{State: gate.phase()}
	}
	if message.Action == "ready" {
		if gate.blocked() {
			return Response{Code: "lifecycle_busy"}
		}
		return Response{State: "ready"}
	}
	switch message.Action {
	case "lease-supersede":
		if uid != 0 {
			return Response{Code: "controller_access_denied"}
		}
		if len(inputs) != 1 {
			return Response{Code: "unexpected_submitted_inputs"}
		}
		return gate.supersede(message.ID, message.NextID, inputs[0])
	case "lease-retire":
		if uid != 0 {
			return Response{Code: "controller_access_denied"}
		}
		return gate.retire(message.ID)
	case "lease-attach":
		if uid != 0 {
			return Response{Code: "controller_access_denied"}
		}
		return gate.attach(message.ID)
	case "lease-applying", "lease-resume", "lease-checking", "lease-release":
		if uid != 0 {
			return Response{Code: "controller_access_denied"}
		}
		phase := map[string]string{"lease-resume": "applying", "lease-applying": "applying", "lease-checking": "checking", "lease-release": "released"}[message.Action]
		if len(inputs) > 1 || (len(inputs) > 0 && phase != "applying") {
			return Response{Code: "unexpected_submitted_inputs"}
		}
		var existing *os.File
		if len(inputs) == 1 {
			existing = inputs[0]
		}
		return gate.transitionWithLock(message.ID, phase, existing, message.Action == "lease-resume")
	}
	if message.Action == "submit" && gate.blocked() {
		return Response{Code: "lifecycle_busy"}
	}
	if !jobID.MatchString(message.ID) {
		return Response{Code: "invalid_operation_id"}
	}
	directory := filepath.Join(state, message.ID)
	switch message.Action {
	case "submit-replica", "stop-replica":
		return Response{Code: "replication_no_longer_supported"}
	case "submit":
		if message.Request == nil || len(inputs) != 3 {
			return Response{Code: "exit_request_required"}
		}
		if existing, statErr := os.Lstat(directory); statErr == nil {
			if !existing.IsDir() || !ownedByProcess(existing) || existing.Mode().Perm()&0077 != 0 {
				return Response{Code: "job_unavailable"}
			}
			if _, markerErr := os.Stat(filepath.Join(directory, "prepared")); os.IsNotExist(markerErr) {
				// Preparation has no side effects on target hosts. A crash before the
				// durable marker can safely be retried from the pinned source inputs.
				if raw, readErr := os.ReadFile(filepath.Join(directory, "request.json")); readErr == nil {
					var previous ExitRequest
					if json.Unmarshal(raw, &previous) != nil {
						return Response{Code: "job_unavailable"}
					}
					a, _ := json.Marshal(previous)
					b, _ := json.Marshal(message.Request)
					if string(a) != string(b) {
						return Response{Code: "operation_conflict"}
					}
				} else if !os.IsNotExist(readErr) {
					return Response{Code: "job_unavailable"}
				}
				if err = os.RemoveAll(directory); err != nil {
					return Response{Code: "job_unavailable"}
				}
			} else if markerErr != nil {
				return Response{Code: "job_unavailable"}
			}
		} else if !os.IsNotExist(statErr) {
			return Response{Code: "job_unavailable"}
		}
		if _, err = os.Lstat(directory); os.IsNotExist(err) {
			if err = prepareInputs(directory, message.Binary, *message.Request, inputs); err != nil {
				return Response{Code: "exit_preparation_failed"}
			}
		} else if err != nil {
			return Response{Code: "job_unavailable"}
		} else {
			// Existing jobs are immutable: never accept a different destination on retry.
			raw, readErr := os.ReadFile(filepath.Join(directory, "request.json"))
			var previous ExitRequest
			if readErr != nil || json.Unmarshal(raw, &previous) != nil {
				return Response{Code: "job_unavailable"}
			}
			a, _ := json.Marshal(previous)
			b, _ := json.Marshal(message.Request)
			if string(a) != string(b) {
				return Response{Code: "operation_conflict"}
			}
			data, err := readInput(inputs[0], 128*1024*1024, false)
			if err != nil {
				return Response{Code: "binary_unavailable"}
			}
			digest := sha256.Sum256(data)
			raw, err = os.ReadFile(filepath.Join(directory, "job.json"))
			var seal map[string]any
			if err != nil || json.Unmarshal(raw, &seal) != nil || seal["binary_sha256"] != hex.EncodeToString(digest[:]) {
				return Response{Code: "operation_conflict"}
			}
		}
	case "status":
	default:
		return Response{Code: "unsupported_operation"}
	}
	data, err = os.ReadFile(filepath.Join(directory, "receipt.json"))
	if os.IsNotExist(err) {
		if _, err = os.Stat(directory); err != nil {
			return Response{Code: "job_unavailable"}
		}
		return Response{State: "queued"}
	}
	var receipt Receipt
	if err != nil || json.Unmarshal(data, &receipt) != nil {
		return Response{Code: "receipt_unavailable"}
	}
	return Response{State: receipt.State, Code: receipt.Code, Result: receipt.Result, Diagnostic: receipt.Diagnostic}
}
