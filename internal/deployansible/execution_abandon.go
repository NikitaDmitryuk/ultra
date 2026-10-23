package deployansible

// A failed generation that wrote a receipt but no completion proof can never be
// reconciled: normal completion is the only automatic proof. This path retires
// the fence only after the caller independently proves that no executor of that
// exact generation survives, and it preserves every original byte as evidence.
import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const executionAbandonmentProtocol = "ultra-execution-abandonment-v1"

// ErrExecutionAbandonmentUnproven means the live quiescence proof failed. The
// fence stays in place.
var ErrExecutionAbandonmentUnproven = errors.New("execution_abandonment_unproven")

// ErrExecutionAbandoned marks a workspace retired as preserved evidence. It
// never authorizes dispatch; continuing requires a new workspace.
var ErrExecutionAbandoned = errors.New("execution_abandoned_requires_new_workspace")

// ExecutionAbandonment records which exact generation was retired and why. It
// is never a completion and never changes the operation outcome.
type ExecutionAbandonment struct {
	SchemaVersion  int            `json:"schema_version"`
	Protocol       string         `json:"protocol"`
	Reason         string         `json:"reason"`
	Fence          ExecutionFence `json:"fence"`
	ReceiptSHA256  string         `json:"receipt_sha256"`
	DispatchSHA256 string         `json:"dispatch_sha256"`
	AttestedAt     int64          `json:"attested_at"`
}

func abandonmentRecordPath(directory string) string {
	return filepath.Join(directory, "execution-abandonment.json")
}

// savedAbandonment returns the recorded abandonment of this workspace, if any.
func savedAbandonment(directory string) (*ExecutionAbandonment, error) {
	raw, err := readRetryPrivate(abandonmentRecordPath(directory))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrExecutionFenced
	}
	var record ExecutionAbandonment
	if json.Unmarshal(raw, &record) != nil || record.SchemaVersion != 1 ||
		record.Protocol != executionAbandonmentProtocol || record.Fence.JobDirectory != directory ||
		len(record.Fence.Generation) != 32 {
		return nil, ErrExecutionFenced
	}
	return &record, nil
}

// AbandonExecutionFence retires one exact failed generation after prove reports
// that nothing of it can still run. prove executes while the admission lock is
// held, so no dispatcher can start between the proof and the retirement.
func AbandonExecutionFence(expected ExecutionFence, prove func(ExecutionFence) error) error {
	if prove == nil || expected.SchemaVersion != 1 || len(expected.Generation) != 32 ||
		!filepath.IsAbs(expected.JobDirectory) || executionReadOnly(expected.Operation) {
		return ErrExecutionAbandonmentUnproven
	}
	root, err := executionRoot(expected.JobDirectory)
	if err != nil {
		return err
	}
	lock, err := controllerLock(filepath.Join(root, "execution-admission.lock"))
	if err != nil {
		return ErrExecutionFenced
	}
	defer lock.Close() //nolint:errcheck
	// A supervised deployment operation is itself an executor of the fleet.
	if err = deploymentExecutionAdmission(root); err != nil {
		return ErrExecutionFenced
	}
	if err = verifyFailedGeneration(root, expected); err != nil {
		return err
	}
	if err = prove(expected); err != nil {
		return ErrExecutionAbandonmentUnproven
	}
	// The proof takes time; re-read the fence, the binding and the evidence.
	if err = verifyFailedGeneration(root, expected); err != nil {
		return err
	}
	return persistAbandonment(root, expected)
}

// RetiredExecution reports the preserved abandonment of this workspace. A
// repeated retirement is then a no-op instead of a second mutation against a
// fence that no longer exists.
func RetiredExecution(directory string) (*ExecutionAbandonment, error) {
	root, err := executionRoot(directory)
	if err != nil {
		return nil, err
	}
	current, err := inspectExecutionFence(root)
	if err != nil || current != nil {
		return nil, err
	}
	return savedAbandonment(directory)
}

// verifyFailedGeneration accepts only a terminal failed receipt of this exact
// generation with no completion, containment, drain or retry evidence.
func verifyFailedGeneration(root string, expected ExecutionFence) error {
	current, err := inspectExecutionFence(root)
	if err != nil || current == nil || *current != expected {
		return ErrExecutionFenced
	}
	binding, err := executionBinding(expected.JobDirectory)
	if err != nil {
		return ErrExecutionFenced
	}
	binding.Generation = expected.Generation
	if binding != expected {
		return ErrExecutionFenced
	}
	raw, err := readRetryPrivate(filepath.Join(expected.JobDirectory, "receipt.json"))
	if err != nil {
		return ErrExecutionFenced
	}
	var receipt struct {
		State      string `json:"state"`
		Generation string `json:"execution_generation"`
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.State != "failed" ||
		receipt.Generation != expected.Generation {
		return ErrExecutionFenced
	}
	// Normal completion belongs to reconcile, retry evidence belongs to retry.
	// Neither may be present here, and this path never creates them.
	for _, pattern := range []string{
		"execution-completion.json",
		"execution-containment.json",
		"execution-drain-*.json",
		"retry-preparation-*.json",
		"execution-abandonment.json",
	} {
		matches, globErr := filepath.Glob(filepath.Join(expected.JobDirectory, pattern))
		if globErr != nil {
			return ErrExecutionFenced
		}
		if len(matches) != 0 {
			return ErrExecutionFenced
		}
	}
	claims, err := filepath.Glob(filepath.Join(expected.JobDirectory, "execution-dispatch-*.json"))
	if err != nil || len(claims) != 1 ||
		filepath.Base(claims[0]) != "execution-dispatch-"+expected.Generation+".json" {
		return ErrExecutionFenced
	}
	dispatch, err := readRetryPrivate(claims[0])
	if err != nil {
		return ErrExecutionFenced
	}
	var claim ExecutionFence
	if json.Unmarshal(dispatch, &claim) != nil || claim != expected {
		return ErrExecutionFenced
	}
	return nil
}

func persistAbandonment(root string, expected ExecutionFence) error {
	receipt, err := readRetryPrivate(filepath.Join(expected.JobDirectory, "receipt.json"))
	if err != nil {
		return ErrExecutionFenced
	}
	dispatch, err := readRetryPrivate(
		filepath.Join(expected.JobDirectory, "execution-dispatch-"+expected.Generation+".json"),
	)
	if err != nil {
		return ErrExecutionFenced
	}
	raw, err := json.Marshal(ExecutionAbandonment{
		SchemaVersion:  1,
		Protocol:       executionAbandonmentProtocol,
		Reason:         "failed_generation_quiescence_attested",
		Fence:          expected,
		ReceiptSHA256:  executionHash(receipt),
		DispatchSHA256: executionHash(dispatch),
		AttestedAt:     time.Now().Unix(),
	})
	if err != nil {
		return ErrExecutionAbandonmentUnproven
	}
	if err = writePrivate(abandonmentRecordPath(expected.JobDirectory), raw); err != nil {
		return err
	}
	if err = syncDirectory(expected.JobDirectory); err != nil {
		return err
	}
	// The fence is renamed, never unlinked: the claim stays readable after the
	// fleet is unfenced, exactly like a remote admission marker.
	if err = writePrivate(
		filepath.Join(root, "execution-fence.abandoned-"+expected.Generation+".json"),
		raw,
	); err != nil {
		return err
	}
	if err = syncDirectory(root); err != nil {
		return err
	}
	if err = os.Remove(filepath.Join(root, "execution-fence.json")); err != nil {
		return err
	}
	return syncDirectory(root)
}

// ProveFailedExecutionQuiescent verifies that this generation left no local
// capability to continue: no live transient containment unit, an empty cgroup,
// and no dispatcher, controller or Ansible worker still running. Remote hosts
// are out of reach here and must be proven by the caller.
func ProveFailedExecutionQuiescent(expected ExecutionFence) error {
	unit := "ultra-execution-" + expected.Generation + ".service"
	values, err := observeContainmentUnit(unit)
	if err != nil {
		return ErrExecutionAbandonmentUnproven
	}
	switch values["LoadState"] {
	case "not-found":
	case "loaded":
		if state := values["ActiveState"]; state != "inactive" && state != "failed" {
			return ErrExecutionAbandonmentUnproven
		}
		if err = emptyContainmentGroup(unit); err != nil {
			return ErrExecutionAbandonmentUnproven
		}
	default:
		return ErrExecutionAbandonmentUnproven
	}
	return proveNoExecutionProcess(expected)
}

func proveNoExecutionProcess(expected ExecutionFence) error {
	excluded := processExclusions()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return ErrExecutionAbandonmentUnproven
	}
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || excluded[pid] {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
		if readErr != nil {
			// A vanished or unreadable process cannot be an executor we own.
			if os.IsNotExist(readErr) || os.IsPermission(readErr) {
				continue
			}
			return ErrExecutionAbandonmentUnproven
		}
		text := string(raw)
		for _, arg := range strings.Split(strings.TrimRight(text, "\x00"), "\x00") {
			switch filepath.Base(arg) {
			case "ansible-playbook", "controller.py", "reconcile.py":
				return ErrExecutionAbandonmentUnproven
			}
		}
		if strings.Contains(text, expected.Generation) || strings.Contains(text, expected.JobDirectory) {
			return ErrExecutionAbandonmentUnproven
		}
	}
	return nil
}

// processExclusions returns every process this census may ignore: the caller's
// own ancestry, which predates the retirement, and its descendants, which the
// retirement itself started. The retiring action necessarily names the
// generation in its own remote leases, so counting them would make the proof
// unsatisfiable rather than strict. A surviving executor of the failed
// generation was started before this process and is never its descendant.
func processExclusions() map[int]bool {
	excluded := processAncestry()
	parents := processParents()
	// Walk every live process towards its root; anything whose chain reaches an
	// excluded process is itself excluded.
	settled := map[int]bool{}
	var descends func(pid int, depth int) bool
	descends = func(pid int, depth int) bool {
		if excluded[pid] {
			return true
		}
		if known, ok := settled[pid]; ok {
			return known
		}
		if depth > 64 {
			return false
		}
		parent, ok := parents[pid]
		if !ok || parent <= 1 || parent == pid {
			settled[pid] = false
			return false
		}
		result := descends(parent, depth+1)
		settled[pid] = result
		return result
	}
	for pid := range parents {
		if descends(pid, 0) {
			excluded[pid] = true
		}
	}
	return excluded
}

// processParents maps each live process to its parent. A process that exits
// during the walk simply disappears from the map, which only widens the census.
func processParents() map[int]int {
	parents := map[int]int{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return parents
	}
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if readErr != nil {
			continue
		}
		end := strings.LastIndex(string(raw), ")")
		if end < 0 {
			continue
		}
		fields := strings.Fields(string(raw)[end+1:])
		if len(fields) < 2 {
			continue
		}
		if parent, parentErr := strconv.Atoi(fields[1]); parentErr == nil {
			parents[pid] = parent
		}
	}
	return parents
}

// processAncestry returns this process and every ancestor, so the operator's own
// command line is never mistaken for a surviving executor.
func processAncestry() map[int]bool {
	seen := map[int]bool{}
	pid := os.Getpid()
	for depth := 0; depth < 64 && pid > 1; depth++ {
		seen[pid] = true
		raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		if err != nil {
			break
		}
		end := strings.LastIndex(string(raw), ")")
		if end < 0 {
			break
		}
		fields := strings.Fields(string(raw)[end+1:])
		if len(fields) < 2 {
			break
		}
		parent, err := strconv.Atoi(fields[1])
		if err != nil || parent == pid {
			break
		}
		pid = parent
	}
	return seen
}
