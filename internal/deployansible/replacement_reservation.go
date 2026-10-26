package deployansible

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

var ErrReplacementReserved = errors.New("replacement_execution_reserved")

const replacementDescriptorEnv = "ULTRA_REPLACEMENT_LEASE_FD"
const replacementIdentityEnv = "ULTRA_REPLACEMENT_LEASE_ID"
const replacementRecordName = "replacement-reservation.json"
const replacementLockName = "replacement-reservation.lock"

type ReplacementBinding struct {
	Workspace     string `json:"workspace"`
	TargetsSHA256 string `json:"targets_sha256"`
	PrimarySHA256 string `json:"primary_sha256"`
}
type ReplacementReservation struct {
	Schema  int                `json:"schema"`
	ID      string             `json:"id"`
	Binding ReplacementBinding `json:"binding"`
	PID     int                `json:"pid"`
	Start   string             `json:"start"`
	Phase   string             `json:"phase"`
}
type replacementLeaseKey struct{}
type ReplacementLease struct {
	file     *os.File
	root     string
	record   ReplacementReservation
	active   atomic.Bool
	imported bool
}

func replacementProcessStart(pid int) (string, error) {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return "", err
	}
	parts := strings.SplitN(string(raw), ") ", 2)
	if len(parts) != 2 {
		return "", ErrReplacementReserved
	}
	fields := strings.Fields(parts[1])
	if len(fields) <= 19 {
		return "", ErrReplacementReserved
	}
	return fields[19], nil
}
func replacementHex(value string, length int) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == length && hex.EncodeToString(decoded) == value
}

func inspectReplacementReservation(root string) (*ReplacementReservation, error) {
	raw, err := readRetryPrivate(filepath.Join(root, replacementRecordName))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrReplacementReserved
	}
	var record ReplacementReservation
	if json.Unmarshal(raw, &record) != nil || record.Schema != 1 || !replacementHex(record.ID, 16) || record.PID <= 0 ||
		record.Start == "" ||
		!filepath.IsAbs(record.Binding.Workspace) ||
		filepath.Clean(record.Binding.Workspace) != record.Binding.Workspace ||
		!replacementHex(record.Binding.TargetsSHA256, 32) ||
		!replacementHex(record.Binding.PrimarySHA256, 32) ||
		(record.Phase != "prepared" && record.Phase != "mutating" && record.Phase != "bootstrap") {
		return nil, ErrReplacementReserved
	}
	return &record, nil
}

// ProveReplacementReservationQuiescent never treats PID reuse or an empty
// flock as completion. Every matching local dispatcher/controller is also
// rejected; the canonical caller must separately prove remote quiescence.
func ProveReplacementReservationQuiescent(record ReplacementReservation) error {
	start, err := replacementProcessStart(record.PID)
	if err == nil && start == record.Start {
		return ErrReplacementReserved
	}
	if err != nil && !os.IsNotExist(err) {
		return ErrReplacementReserved
	}
	return proveNoExecutionProcess(ExecutionFence{Generation: record.ID, JobDirectory: record.Binding.Workspace})
}

// ReserveReplacement serializes all supported mutation dispatch through the
// complete replacement, including the interval after old-generation retirement.
// A durable record fences a killed owner; only another canonical replacement
// may validate and take over that exact record. No ordinary dispatcher clears it.
func ReserveReplacement(
	ctx context.Context,
	binding ReplacementBinding,
	validatePrevious func(ReplacementReservation) error,
) (context.Context, *ReplacementLease, error) {
	root, err := executionRoot("")
	if err != nil {
		return ctx, nil, err
	}
	file, err := controllerLock(filepath.Join(root, replacementLockName))
	if err != nil {
		return ctx, nil, ErrReplacementReserved
	}
	fail := func(err error) (context.Context, *ReplacementLease, error) { _ = file.Close(); return ctx, nil, err }
	previous, err := inspectReplacementReservation(root)
	if err != nil {
		return fail(err)
	}
	if previous != nil {
		if validatePrevious == nil {
			return fail(ErrReplacementReserved)
		}
		if err = ProveReplacementReservationQuiescent(*previous); err != nil {
			return fail(err)
		}
		if err = validatePrevious(*previous); err != nil {
			return fail(err)
		}
	}
	if !filepath.IsAbs(binding.Workspace) || filepath.Clean(binding.Workspace) != binding.Workspace ||
		!replacementHex(binding.TargetsSHA256, 32) ||
		!replacementHex(binding.PrimarySHA256, 32) {
		return fail(ErrReplacementReserved)
	}
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return fail(err)
	}
	start, err := replacementProcessStart(os.Getpid())
	if err != nil {
		return fail(err)
	}
	phase := "prepared"
	// Taking over an uncertain parent must not erase its remote uncertainty if
	// this new process fails before completing fresh fencing and proof.
	if previous != nil && previous.Phase != "prepared" {
		phase = "mutating"
	}
	record := ReplacementReservation{
		Schema:  1,
		ID:      hex.EncodeToString(nonce),
		Binding: binding,
		PID:     os.Getpid(),
		Start:   start,
		Phase:   phase,
	}
	if previous != nil {
		path := filepath.Join(root, "replacement-reservation.superseded-"+previous.ID+".json")
		if raw, readErr := readRetryPrivate(path); readErr == nil {
			var archived ReplacementReservation
			if json.Unmarshal(raw, &archived) != nil || archived != *previous {
				return fail(ErrReplacementReserved)
			}
		} else if !os.IsNotExist(readErr) {
			return fail(ErrReplacementReserved)
		} else if err = writeJSON(path, previous); err != nil {
			return fail(err)
		}
	}
	if err = replaceReservationRecord(root, record); err != nil {
		return fail(err)
	}
	lease := &ReplacementLease{file: file, root: root, record: record}
	lease.active.Store(true)
	return context.WithValue(ctx, replacementLeaseKey{}, lease), lease, nil
}
func replaceReservationRecord(root string, record ReplacementReservation) error {
	raw, err := json.Marshal(record)
	if err != nil {
		return err
	}
	file, err := os.CreateTemp(root, ".replacement-reservation-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name) //nolint:errcheck
	if _, err = file.Write(raw); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, filepath.Join(root, replacementRecordName)); err != nil {
		return err
	}
	return syncDirectory(root)
}
func (lease *ReplacementLease) valid() error {
	if lease == nil || !lease.active.Load() {
		return ErrReplacementReserved
	}
	record, err := inspectReplacementReservation(lease.root)
	if err != nil || record == nil || *record != lease.record {
		return ErrReplacementReserved
	}
	return nil
}
func (lease *ReplacementLease) SetPhase(phase string) error {
	if err := lease.valid(); err != nil {
		return err
	}
	if lease.imported || phase != "mutating" && phase != "bootstrap" {
		return ErrReplacementReserved
	}
	lease.record.Phase = phase
	return replaceReservationRecord(lease.root, lease.record)
}
func (lease *ReplacementLease) Finish() error {
	if err := lease.valid(); err != nil {
		return err
	}
	if lease.imported {
		return ErrReplacementReserved
	}
	if err := os.Remove(filepath.Join(lease.root, replacementRecordName)); err != nil {
		return err
	}
	return syncDirectory(lease.root)
}
func (lease *ReplacementLease) Close() error {
	if lease != nil && lease.active.Swap(false) {
		return lease.file.Close()
	}
	return nil
}
func (lease *ReplacementLease) SafeToFinish() bool {
	return lease != nil && lease.record.Phase == "prepared"
}

// Handoff grants only a direct child the same locked open-file-description.
// Environment fields identify the grant; possession and ownership of its FD,
// exact private record and parent PID/start identity authenticate it.
func (lease *ReplacementLease) Handoff(command *exec.Cmd) error {
	if err := lease.valid(); err != nil {
		return err
	}
	if lease.imported || lease.record.Phase != "bootstrap" {
		return ErrReplacementReserved
	}
	if command.Env == nil {
		command.Env = os.Environ()
	}
	clean := command.Env[:0]
	for _, entry := range command.Env {
		if !strings.HasPrefix(entry, replacementDescriptorEnv+"=") && !strings.HasPrefix(entry, replacementIdentityEnv+"=") {
			clean = append(clean, entry)
		}
	}
	command.Env = clean
	command.ExtraFiles = append(command.ExtraFiles, lease.file)
	command.Env = append(
		command.Env,
		replacementDescriptorEnv+"="+strconv.Itoa(2+len(command.ExtraFiles)),
		replacementIdentityEnv+"="+lease.record.ID,
	)
	return nil
}
func ImportReplacementReservation(ctx context.Context, stateRoot string) (context.Context, func(), error) {
	text, id := os.Getenv(replacementDescriptorEnv), os.Getenv(replacementIdentityEnv)
	if text == "" && id == "" {
		return ctx, func() {}, nil
	}
	fd, err := strconv.Atoi(text)
	if err != nil || fd < 3 {
		return ctx, nil, ErrReplacementReserved
	}
	offered := os.NewFile(uintptr(fd), "replacement-lease")
	if offered == nil {
		return ctx, nil, ErrReplacementReserved
	}
	defer offered.Close() //nolint:errcheck
	root := executionFenceDirectory("")
	record, err := inspectReplacementReservation(root)
	if err != nil || record == nil || record.ID != id || record.Phase != "bootstrap" || record.PID != os.Getppid() ||
		stateRoot != filepath.Join(record.Binding.Workspace, "bootstrap") {
		return ctx, nil, ErrReplacementReserved
	}
	start, err := replacementProcessStart(record.PID)
	if err != nil || start != record.Start {
		return ctx, nil, ErrReplacementReserved
	}
	// An independent open must be excluded by the inherited EX lock; then the
	// offered descriptor must itself be able to retain that same EX description.
	independent, err := os.OpenFile(filepath.Join(root, replacementLockName), os.O_RDWR, 0600)
	if err != nil {
		return ctx, nil, ErrReplacementReserved
	}
	blocked := syscall.Flock(int(independent.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	_ = independent.Close()
	if blocked == nil || !controllerLockBusy(blocked) {
		return ctx, nil, ErrReplacementReserved
	}
	retained, err := retainInfrastructureLock(offered, filepath.Join(root, replacementLockName))
	if err != nil {
		return ctx, nil, ErrReplacementReserved
	}
	lease := &ReplacementLease{file: retained, root: root, record: *record, imported: true}
	lease.active.Store(true)
	return context.WithValue(ctx, replacementLeaseKey{}, lease), func() { _ = lease.Close() }, nil
}

func replacementDispatchAdmission(ctx context.Context, root, directory string) (func(), error) {
	if lease, ok := ctx.Value(replacementLeaseKey{}).(*ReplacementLease); ok {
		if lease.root != root || lease.valid() != nil {
			return nil, ErrReplacementReserved
		}
		relative, err := filepath.Rel(filepath.Join(lease.record.Binding.Workspace, "bootstrap"), directory)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return nil, ErrReplacementReserved
		}
		return func() {}, nil
	}
	fd, err := syscall.Open(
		filepath.Join(root, replacementLockName),
		syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC,
		0600,
	)
	if err != nil {
		return nil, ErrReplacementReserved
	}
	file := os.NewFile(uintptr(fd), replacementLockName)
	if err = syscall.Flock(fd, syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, ErrReplacementReserved
	}
	record, err := inspectReplacementReservation(root)
	if err != nil || record != nil {
		_ = file.Close()
		return nil, ErrReplacementReserved
	}
	return func() { _ = file.Close() }, nil
}

// RetainReplacementSSH keeps the reservation alive in a local supervisor even
// though OpenSSH closes inherited extra descriptors itself. No grant variables
// are added: this child can retain the lock, never admit a bootstrap operation.
// The generation in argv also makes an orphan supervisor visible to the census.
func RetainReplacementSSH(ctx context.Context, command *exec.Cmd) error {
	lease, ok := ctx.Value(replacementLeaseKey{}).(*ReplacementLease)
	if !ok {
		return nil
	}
	if err := lease.valid(); err != nil {
		return err
	}
	if command.SysProcAttr != nil {
		return ErrReplacementReserved
	}
	original := append([]string{command.Path}, command.Args[1:]...)
	timeout := 60 * time.Second
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) < timeout {
		timeout = time.Until(deadline)
	}
	if timeout <= 0 {
		return context.DeadlineExceeded
	}
	const supervisor = `import os,signal,subprocess,sys
p=subprocess.Popen(sys.argv[3:])
try:
 rc=p.wait(timeout=float(sys.argv[2]))
except subprocess.TimeoutExpired:
 os.killpg(0,signal.SIGKILL)
sys.exit(rc if rc >= 0 else 128-rc)
`
	command.Path = "/usr/bin/python3"
	command.Args = append(
		[]string{command.Path, "-I", "-c", supervisor, lease.record.ID, strconv.FormatFloat(timeout.Seconds(), 'f', 6, 64)},
		original...)
	command.ExtraFiles = append(command.ExtraFiles, lease.file)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	return nil
}
