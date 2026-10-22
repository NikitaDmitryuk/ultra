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
	"sort"
	"strconv"
	"strings"
	"time"
)

// Client submits jobs to a root-owned systemd worker. The worker survives relay restarts.
type Client struct{ Socket string }
type Message struct {
	leaseInputs        []*os.File
	Action             string                         `json:"action"`
	ID                 string                         `json:"id"`
	NextID             string                         `json:"next_id,omitempty"`
	Binary             string                         `json:"binary,omitempty"`
	Request            *ExitRequest                   `json:"request,omitempty"`
	NodeID             string                         `json:"node_id,omitempty"`
	RecoveryFence      *SignedRecoveryFenceRequest    `json:"recovery_fence,omitempty"`
	RecoveryCompletion *SignedRecoveryFenceCompletion `json:"recovery_completion,omitempty"`
}
type Response struct {
	leaseOutputs []*os.File
	Diagnostic   Diagnostic `json:"diagnostic,omitempty"`
	State        string     `json:"state"`
	Code         string     `json:"code,omitempty"`
	Result       Result     `json:"result,omitempty"`
}

// Result is a value type with custom JSON decoding, so omitempty alone does
// not omit its zero value. An uncertain projection must carry no result at all.
func (r Response) MarshalJSON() ([]byte, error) {
	if r.State == "running" && r.Code == "execution_uncertain_reconciliation_required" {
		return json.Marshal(struct {
			State string `json:"state"`
			Code  string `json:"code"`
		}{r.State, r.Code})
	}
	type response Response
	return json.Marshal(response(r))
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
	// A raw terminal receipt may precede its cleanup proof by a short window.
	// Only job observations may continue polling this exact nonterminal reply;
	// lifecycle actions and all other errors retain their existing semantics.
	pendingCleanup := (message.Action == "submit" || message.Action == "status") &&
		response.State == "running" && response.Code == "execution_uncertain_reconciliation_required"
	if response.Code != "" && !pendingCleanup {
		closeInputs(outputs)
		if response.Diagnostic.Code != "" {
			return response, fmt.Errorf("%s (%s: %s; %s)", response.Code,
				response.Diagnostic.Node, response.Diagnostic.Stage, response.Diagnostic.Code)
		}
		return response, fmt.Errorf("%s (%s: %s)", response.Code, response.Diagnostic.Node, response.Diagnostic.Stage)
	}
	leaseReply := message.Action == "lease-attach" || message.Action == "lease-observe"
	if (leaseReply && len(outputs) != 1) || (!leaseReply && len(outputs) != 0) {
		closeInputs(outputs)
		return Response{}, errors.New("unexpected controller descriptors")
	}
	response.leaseOutputs = outputs
	return response, nil
}

// ReadinessError exposes only a fixed readiness classification to API consumers.
type ReadinessError struct {
	code  string
	cause error
}

func (e *ReadinessError) Error() string         { return e.code }
func (e *ReadinessError) Unwrap() error         { return e.cause }
func (e *ReadinessError) ReadinessCode() string { return e.code }

func (c Client) Ready(ctx context.Context) error {
	response, err := c.exchange(ctx, Message{Action: "ready"})
	if err == nil {
		return nil
	}
	code := "controller_unavailable"
	if response.Code == "lifecycle_busy" {
		code = "lifecycle_busy"
	}
	return &ReadinessError{code: code, cause: err}
}

// ConfigurationTerminal reads the durable receipt, including terminal failures
// whose diagnostic code makes exchange return an error alongside the response.
func (c Client) ConfigurationTerminal(ctx context.Context, id string) (bool, error) {
	response, err := c.exchange(ctx, Message{Action: "status", ID: id})
	switch response.State {
	case "succeeded", "failed":
		return true, nil
	case "queued", "running":
		return false, err
	default:
		if err != nil {
			return false, err
		}
		return false, errors.New("configuration receipt unavailable")
	}
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
				lease := &operationLease{directory: state, file: operationLock}
				lease.active.Store(true)
				jobContext := context.WithValue(ctx, operationLeaseKey{}, lease)
				_, runErr := Execute(jobContext, directory, python, executable)
				lease.active.Store(false)
				_ = operationLock.Close()
				if runErr != nil && !errors.Is(runErr, ErrExecutionFenced) && ctx.Err() == nil {
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
	if message.Action == "recovery-fence-import" || message.Action == "recovery-fence-complete" {
		if uid != 0 {
			return Response{Code: "controller_access_denied"}
		}
		if message.Action == "recovery-fence-import" && message.RecoveryFence != nil && message.RecoveryCompletion == nil {
			return gate.importRecoveryFence(*message.RecoveryFence)
		}
		if message.Action == "recovery-fence-complete" && message.RecoveryCompletion != nil && message.RecoveryFence == nil {
			return gate.completeRecoveryFence(*message.RecoveryCompletion)
		}
		return Response{Code: "invalid_recovery_request"}
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
	case "lease-observe":
		if uid != 0 {
			return Response{Code: "controller_access_denied"}
		}
		return gate.observe(message.ID)
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
	if message.Action == "submit" {
		admission, fenceErr := recoveryAdmission(state)
		if fenceErr != nil {
			return Response{Code: "recovery_fenced"}
		}
		defer admission()
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
				if err = executionAdmission(directory); err != nil {
					return Response{Code: "execution_uncertain_reconciliation_required"}
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
			if err = executionAdmission(directory); err != nil {
				return Response{Code: "execution_uncertain_reconciliation_required"}
			}
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
	return projectControllerReceipt(directory, data, receipt)
}

// A task receipt precedes systemd cleanup. Project terminal state only from
// already committed evidence; status never runs a census, reconciles or writes.
func projectControllerReceipt(directory string, raw []byte, receipt Receipt) Response {
	if (receipt.State == "succeeded" || receipt.State == "failed") && !controllerTerminalVerified(directory, raw) {
		return Response{State: "running", Code: "execution_uncertain_reconciliation_required"}
	}
	return Response{State: receipt.State, Code: receipt.Code, Result: receipt.Result, Diagnostic: receipt.Diagnostic}
}
func controllerTerminalVerified(directory string, raw []byte) bool {
	var metadata struct {
		Generation string `json:"execution_generation"`
	}
	if json.Unmarshal(raw, &metadata) != nil {
		return false
	}
	// Do not use executionRoot/InspectExecutionFence: those may create state.
	current, err := inspectExecutionFence(executionFenceDirectory(directory))
	if err != nil {
		return false
	}
	if current != nil && (current.JobDirectory == directory || metadata.Generation != "" && current.Generation == metadata.Generation) {
		return false
	}
	if metadata.Generation == "" {
		// Genuine legacy and read-only receipts have no execution evidence. A
		// truncated modern receipt cannot erase its generation to gain this path.
		entries, err := os.ReadDir(directory)
		if err != nil {
			return false
		}
		for _, entry := range entries {
			name := entry.Name()
			if name == "execution-completion.json" || name == "execution-containment.json" ||
				strings.HasPrefix(name, "execution-dispatch-") || strings.HasPrefix(name, "execution-drain-") {
				return false
			}
		}
		return true
	}
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(metadata.Generation) {
		return false
	}
	// The proof identifies the exact frozen job; completion validation checks
	// the current job/request/bundle, receipt hash and normal rc0/rc2 outcome.
	proofRaw, err := readRetryPrivate(filepath.Join(directory, "execution-containment.json"))
	if err != nil {
		return false
	}
	var saved struct {
		Fence ExecutionFence `json:"fence"`
	}
	if json.Unmarshal(proofRaw, &saved) != nil || saved.Fence.JobDirectory != directory || saved.Fence.Generation != metadata.Generation {
		return false
	}
	proof, err := readContainmentProof(saved.Fence)
	if err != nil {
		return false
	}
	verified, err := verifiedContainment(proof)
	// Do not invoke containment recovery, including if evidence changes while
	// Status is reading it. This path consumes committed evidence only.
	return err == nil && verified && validateControllerHistoricalTerminal(saved.Fence) == nil
}

// Historical RPC state consumes the frozen ownership inventory, not executable
// payloads which normal retention may already have collected. This is never an
// authority for dispatch, retry, execution completion or fence reconciliation.
func validateControllerHistoricalTerminal(expected ExecutionFence) error {
	jobRaw, err := readRetryPrivate(filepath.Join(expected.JobDirectory, "job.json"))
	if err != nil || executionHash(jobRaw) != expected.JobSHA256 {
		return ErrExecutionFenced
	}
	var job struct {
		Schema    int    `json:"schema_version"`
		Operation string `json:"operation"`
		Request   string `json:"request_sha256"`
		Attempt   int    `json:"attempt"`
	}
	if json.Unmarshal(jobRaw, &job) != nil || job.Schema != 1 {
		return ErrExecutionFenced
	}
	if job.Attempt == 0 {
		job.Attempt = 1
	}
	requestRaw, err := readRetryPrivate(filepath.Join(expected.JobDirectory, "request.json"))
	if err != nil || job.Operation != expected.Operation || job.Attempt != expected.Attempt || job.Request != expected.RequestSHA256 ||
		executionHash(requestRaw) != expected.RequestSHA256 || executionHash(requestRaw) != expected.InventorySHA256 {
		return ErrExecutionFenced
	}
	raw, err := readRetryPrivate(filepath.Join(expected.JobDirectory, "bundle.retention.json"))
	if err != nil {
		return ErrExecutionFenced
	}
	var ownership struct {
		Schema    int                          `json:"schema"`
		Path      string                       `json:"path"`
		Identity  map[string]string            `json:"identity"`
		Inventory map[string][]json.RawMessage `json:"inventory"`
	}
	if json.Unmarshal(raw, &ownership) != nil || ownership.Schema != 1 ||
		ownership.Path != filepath.Join(expected.JobDirectory, "bundle") ||
		len(ownership.Identity) != 1 ||
		ownership.Identity["request_sha256"] != expected.RequestSHA256 ||
		len(ownership.Inventory) == 0 {
		return ErrExecutionFenced
	}
	names := make([]string, 0, len(ownership.Inventory))
	for name := range ownership.Inventory {
		names = append(names, name)
	}
	sort.Strings(names)
	hash := sha256.New()
	for _, name := range names {
		if name == "." || filepath.IsAbs(name) || filepath.ToSlash(filepath.Clean(name)) != name || strings.HasPrefix(name, "../") {
			return ErrExecutionFenced
		}
		entry := ownership.Inventory[name]
		if len(entry) < 2 {
			return ErrExecutionFenced
		}
		var kind string
		if json.Unmarshal(entry[0], &kind) != nil {
			return ErrExecutionFenced
		}
		var mode uint32
		switch kind {
		case "directory":
			if len(entry) != 2 || json.Unmarshal(entry[1], &mode) != nil {
				return ErrExecutionFenced
			}
		case "file":
			var digest string
			if len(entry) != 3 || json.Unmarshal(entry[1], &digest) != nil || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(digest) ||
				json.Unmarshal(entry[2], &mode) != nil {
				return ErrExecutionFenced
			}
			hash.Write([]byte(name))
			hash.Write([]byte{0})
			hash.Write([]byte(digest))
			hash.Write([]byte{'\n'})
		default:
			return ErrExecutionFenced
		}
		if mode > 0777 || mode&0022 != 0 {
			return ErrExecutionFenced
		}
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected.BundleSHA256 {
		return ErrExecutionFenced
	}
	return validateExecutionReceipt(expected)
}
