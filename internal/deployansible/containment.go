package deployansible

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var approvedExecutionGroup = regexp.MustCompile(
	`^0::/system.slice/ultra-(deploy-[a-f0-9]{64}|ansible-controller|recovery-reconcile)\.service$`,
)

var errExecutionContainmentStopUnverified = errors.New("execution_containment_stop_unverified")

func executionContainmentPreflight() error {
	if err := requireConfiguredExecutionState(); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		info, err := os.Lstat("/run/user/" + strconv.Itoa(os.Geteuid()))
		if err != nil || !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm() != 0700 {
			return errors.New("execution_containment_unavailable")
		}
	}
	for _, path := range []string{"/usr/bin/systemctl", "/usr/bin/systemd-run"} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || !ownedByRoot(info) || info.Mode().Perm()&0022 != 0 || info.Mode().Perm()&0111 == 0 {
			return errors.New("execution_containment_unavailable")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := executionManagerCommand(
		exec.CommandContext(ctx, "/usr/bin/systemctl", executionManagerArgs("show", "--property=Version", "--value")...),
	).Output()
	if err != nil || strings.TrimSpace(string(raw)) == "" {
		return errors.New("execution_containment_unavailable")
	}
	return nil
}

// PreflightLocalExecution reports whether this process can dispatch a contained
// standalone operation. Callers must run it before creating a durable remote
// fence: otherwise a non-root run passes every CLI and SSH check, fences the
// fleet, and only then aborts inside beginExecution with no receipt to explain it.
func PreflightLocalExecution() error {
	root := executionFenceDirectory("")
	if executionNamespaceFixture() {
		return nil
	}
	if err := executionContainmentPreflight(); err != nil {
		return err
	}
	info, err := os.Lstat(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
		return errors.New("execution_namespace_insecure")
	}
	return nil
}

func ownedByRoot(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}

// Python independently attests the actual unit, owner, command and KillMode
// before dispatch. Standalone callers get one unit for the already frozen job.
func runContainedController(ctx context.Context, command *exec.Cmd, fence *ExecutionFence) error {
	if fence == nil || executionNamespaceFixture() {
		return command.Run()
	}
	group, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(group), "\n") {
		if approvedExecutionGroup.MatchString(line) {
			return command.Run()
		}
	}
	if !filepath.IsAbs(command.Path) || len(fence.Generation) != 32 ||
		strings.Trim(fence.Generation, "0123456789abcdef") != "" {
		return errors.New("execution_containment_unverified")
	}
	unit := "ultra-execution-" + fence.Generation + ".service"
	timeout, err := preparedExecutionTimeout(fence.JobDirectory)
	if err != nil {
		return err
	}
	// Keep failed units loaded until their Result has been durably observed.
	args := []string{"--unit=" + unit, "--wait", "--pipe", "--service-type=exec",
		"--property=KillMode=control-group", "--property=Delegate=no", "--property=UMask=0077",
		"--property=TimeoutStopSec=30", "--property=RuntimeMaxSec=" + strconv.FormatInt(int64(timeout/time.Second), 10), "--property=Restart=no"}
	if os.Geteuid() != 0 {
		root, stateErr := ExpectedLocalExecutionState()
		if stateErr != nil {
			return stateErr
		}
		command.Env = append(command.Env, "ULTRA_OPERATOR_STATE_DIRECTORY="+root)
		args = append(executionManagerArgs(), args...)
		args = append(args, "--property=Slice=app.slice")
	}
	for _, value := range command.Env {
		args = append(args, "--setenv="+value)
	}
	args = append(args, "--", command.Path)
	args = append(args, command.Args[1:]...)
	contained := exec.CommandContext(ctx, "/usr/bin/systemd-run", args...)
	contained.Stdin, contained.Stdout, contained.Stderr = command.Stdin, command.Stdout, command.Stderr
	executionManagerCommand(contained)
	contained.Cancel = func() error { return stopExecutionUnit(unit) }
	contained.WaitDelay = 5 * time.Second
	err = contained.Run()
	limitErr := observeExecutionRuntimeLimit(*fence)
	if limitErr != nil {
		return errors.Join(err, limitErr)
	}
	// Exit status (including normal rc2) and cleanup are independent facts.
	// No proof is published if the stop/drain observation fails.
	return completeContainedExecution(*fence, unit, err, stopExecutionUnit)
}
func completeContainedExecution(fence ExecutionFence, unit string, runErr error, drain func(string) error) error {
	if drainErr := drain(unit); drainErr != nil {
		return errors.Join(runErr, errExecutionContainmentStopUnverified, drainErr)
	}
	if proofErr := finalizeTransientContainment(fence, unit); proofErr != nil {
		return errors.Join(runErr, proofErr)
	}
	return runErr
}

func stopExecutionUnit(unit string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	stopErr := executionManagerCommand(exec.CommandContext(ctx, "/usr/bin/systemctl", executionManagerArgs("stop", unit)...)).Run()
	raw, err := executionManagerCommand(exec.CommandContext(ctx, "/usr/bin/systemctl", executionManagerArgs("show", unit,
		"--property=LoadState", "--property=ActiveState", "--property=ControlGroup")...)).Output()
	if err != nil {
		return errors.Join(errExecutionContainmentStopUnverified, stopErr, err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			values[key] = value
		}
	}
	if values["LoadState"] != "not-found" && values["ActiveState"] != "inactive" && values["ActiveState"] != "failed" {
		return errExecutionContainmentStopUnverified
	}
	group, err := executionUnitGroup(unit, values["ControlGroup"])
	if err != nil {
		return errExecutionContainmentStopUnverified
	}
	events, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", group, "cgroup.events"))
	if err == nil && !strings.Contains(string(events), "populated 0\n") || err != nil && !os.IsNotExist(err) {
		return errExecutionContainmentStopUnverified
	}
	return nil
}

// Containment evidence is separate from Ansible's terminal outcome. A normal
// callback cannot authorize retirement after an unverified systemd drain.
type containmentProcess struct {
	PID              int    `json:"pid"`
	Parent           int    `json:"parent"`
	Starttime        string `json:"starttime"`
	Group            string `json:"group"`
	ExecutableSHA256 string `json:"executable_sha256"`
	ArgvSHA256       string `json:"argv_sha256"`
}
type containmentProof struct {
	Schema       int                  `json:"schema"`
	Manager      string               `json:"manager,omitempty"`
	UID          int                  `json:"uid,omitempty"`
	ControlGroup string               `json:"control_group,omitempty"`
	Fence        ExecutionFence       `json:"fence"`
	Mode         string               `json:"mode"`
	Unit         string               `json:"unit"`
	InvocationID string               `json:"invocation_id"`
	Chain        []containmentProcess `json:"chain"`
}

func readContainmentProof(fence ExecutionFence) (containmentProof, error) {
	var proof containmentProof
	raw, err := readRetryPrivate(filepath.Join(fence.JobDirectory, "execution-containment.json"))
	if err != nil {
		return proof, err
	}
	if json.Unmarshal(raw, &proof) != nil || (proof.Schema != 1 && proof.Schema != 2) || proof.Fence != fence ||
		!regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(proof.InvocationID) {
		return proof, ErrExecutionFenced
	}
	if _, err = containmentProofGroup(proof); err != nil {
		return proof, err
	}
	return proof, nil
}
func finalizeTransientContainment(fence ExecutionFence, unit string) error {
	proof, err := readContainmentProof(fence)
	if err != nil || proof.Unit != unit || proof.Mode != "transient" ||
		(os.Geteuid() != 0 && !executionNamespaceFixture() && proof.Schema != 2) {
		return ErrExecutionFenced
	}
	return persistVerifiedContainment(proof)
}

// Test fixtures may replace the observer, never production namespace selection.
var observeContainmentUnit = containmentUnitState

func containmentUnitState(unit string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := executionManagerCommand(
		exec.CommandContext(
			ctx,
			"/usr/bin/systemctl",
			executionManagerArgs(
				"show",
				unit,
				"--property=LoadState",
				"--property=ActiveState",
				"--property=ControlGroup",
				"--property=KillMode",
				"--property=Delegate",
				"--property=User",
				"--property=MainPID",
				"--property=InvocationID",
				"--property=Result",
			)...),
	).Output()
	if err != nil {
		return nil, err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			values[k] = v
		}
	}
	return values, nil
}
func emptyContainmentGroup(unit string) error {
	values, err := observeContainmentUnit(unit)
	if err != nil {
		return ErrExecutionFenced
	}
	group, err := executionUnitGroup(unit, values["ControlGroup"])
	if err != nil {
		return err
	}
	events, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", group, "cgroup.events"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !strings.Contains(string(events), "populated 0\n") {
		return ErrExecutionFenced
	}
	return nil
}
func readContainmentProcess(pid int) (containmentProcess, error) {
	var result containmentProcess
	base := filepath.Join("/proc", strconv.Itoa(pid))
	raw, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return result, err
	}
	end := strings.LastIndex(string(raw), ")")
	if end < 0 {
		return result, ErrExecutionFenced
	}
	fields := strings.Fields(string(raw)[end+1:])
	if len(fields) < 20 {
		return result, ErrExecutionFenced
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return result, err
	}
	status, err := os.ReadFile(filepath.Join(base, "status"))
	if err != nil {
		return result, err
	}
	uidOK := false
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			uidOK = strings.Join(strings.Fields(line)[1:], " ") == strings.TrimSpace(strings.Repeat(strconv.Itoa(os.Geteuid())+" ", 4))
		}
	}
	if !uidOK {
		return result, ErrExecutionFenced
	}
	groups, err := os.ReadFile(filepath.Join(base, "cgroup"))
	if err != nil {
		return result, err
	}
	group := ""
	for _, line := range strings.Split(string(groups), "\n") {
		if strings.HasPrefix(line, "0::") {
			if group != "" {
				return result, ErrExecutionFenced
			}
			group = line[3:]
		}
	}
	exe, err := os.ReadFile(filepath.Join(base, "exe"))
	if err != nil {
		return result, err
	}
	argv, err := os.ReadFile(filepath.Join(base, "cmdline"))
	if err != nil {
		return result, err
	}
	return containmentProcess{pid, parent, fields[19], group, executionHash(exe), executionHash(argv)}, nil
}
func containmentProofGroup(proof containmentProof) (string, error) {
	group := "/system.slice/" + proof.Unit
	if proof.Schema == 2 {
		if proof.Manager != "user" || proof.UID <= 0 || proof.UID != os.Geteuid() {
			return "", ErrExecutionFenced
		}
		expected, err := executionUnitGroup(proof.Unit, proof.ControlGroup)
		if err != nil || proof.ControlGroup == "" {
			return "", ErrExecutionFenced
		}
		group = expected
	} else if proof.Schema != 1 || proof.Manager != "" || proof.UID != 0 || proof.ControlGroup != "" {
		return "", ErrExecutionFenced
	}
	return group, nil
}
func verifyContainmentProof(proof containmentProof) error {
	// A committed exact drain receipt can authenticate imported historical root
	// evidence. A user manager can never establish new facts about root workers.
	if proof.Schema == 1 && os.Geteuid() != 0 && !executionNamespaceFixture() {
		return ErrExecutionFenced
	}
	group, err := containmentProofGroup(proof)
	if err != nil {
		return err
	}
	transient := proof.Mode == "transient" && proof.Unit == "ultra-execution-"+proof.Fence.Generation+".service"
	reuse := proof.Schema == 1 && proof.Mode == "reuse" && approvedExecutionGroup.MatchString("0::/system.slice/"+proof.Unit)
	if !transient && !reuse {
		return ErrExecutionFenced
	}
	if len(proof.Chain) == 0 || len(proof.Chain) > 64 {
		return ErrExecutionFenced
	}
	seen := map[int]bool{}
	for i, member := range proof.Chain {
		if member.PID <= 0 || member.Parent < 0 || seen[member.PID] || member.Group != group ||
			!regexp.MustCompile(`^[0-9]+$`).MatchString(member.Starttime) ||
			!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(member.ExecutableSHA256) ||
			!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(member.ArgvSHA256) {
			return ErrExecutionFenced
		}
		seen[member.PID] = true
		if i+1 < len(proof.Chain) && member.Parent != proof.Chain[i+1].PID {
			return ErrExecutionFenced
		}
	}
	values, err := observeContainmentUnit(proof.Unit)
	if err != nil {
		return ErrExecutionFenced
	}
	if values["LoadState"] == "not-found" || values["ActiveState"] == "inactive" || values["ActiveState"] == "failed" {
		return emptyContainmentGroup(proof.Unit)
	}
	if !reuse || values["LoadState"] != "loaded" || values["ActiveState"] != "active" && values["ActiveState"] != "activating" ||
		values["ControlGroup"] != group || values["KillMode"] != "control-group" || values["Delegate"] != "no" ||
		values["User"] != "" &&
			values["User"] != "root" || values["InvocationID"] != proof.InvocationID || len(proof.Chain) == 0 || len(proof.Chain) > 64 {
		return ErrExecutionFenced
	}
	owner := proof.Chain[len(proof.Chain)-1]
	if values["MainPID"] != strconv.Itoa(owner.PID) {
		return ErrExecutionFenced
	}
	allowed := map[int]containmentProcess{}
	for i, member := range proof.Chain {
		if member.PID <= 0 || member.Group != group {
			return ErrExecutionFenced
		}
		if _, ok := allowed[member.PID]; ok {
			return ErrExecutionFenced
		}
		if i+1 < len(proof.Chain) && member.Parent != proof.Chain[i+1].PID {
			return ErrExecutionFenced
		}
		allowed[member.PID] = member
	}
	for pass := 0; pass < 2; pass++ {
		for pid, member := range allowed {
			current, err := observeContainmentProcess(pid)
			if os.IsNotExist(err) && pid != owner.PID {
				continue
			}
			if err != nil || current != member {
				return ErrExecutionFenced
			}
		}
		members, err := observeContainmentMembers(proof.Unit)
		if err != nil {
			return ErrExecutionFenced
		}
		for _, pid := range members {
			if _, ok := allowed[pid]; !ok {
				return errors.New("execution_containment_workers_live")
			}
		}

	}
	return nil
}
func validateExecutionContainment(fence ExecutionFence) error {
	proof, err := readContainmentProof(fence)
	// Private fixture roots do not run under the host systemd manager. If a
	// fixture supplies evidence, validate it exactly as production does.
	if os.IsNotExist(err) && executionNamespaceFixture() {
		return nil
	}
	if err != nil {
		return ErrExecutionFenced
	}
	if verified, e := verifiedContainment(proof); e != nil {
		return ErrExecutionFenced
	} else if verified {
		return nil
	}

	return verifyContainmentProof(proof)
}

type verifiedContainmentReceipt struct {
	Proof            containmentProof `json:"proof"`
	CompletionSHA256 string           `json:"completion_sha256"`
}

func verifiedContainment(proof containmentProof) (bool, error) {
	raw, err := readRetryPrivate(filepath.Join(proof.Fence.JobDirectory, "execution-drain-"+proof.Fence.Generation+".json"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	completion, err := readRetryPrivate(filepath.Join(proof.Fence.JobDirectory, "execution-completion.json"))
	if err != nil {
		return false, err
	}
	var prior verifiedContainmentReceipt
	if json.Unmarshal(raw, &prior) != nil || !reflect.DeepEqual(prior.Proof, proof) || prior.CompletionSHA256 != executionHash(completion) {
		return false, ErrExecutionFenced
	}
	return true, nil
}
func persistVerifiedContainment(proof containmentProof) error {
	if verified, err := verifiedContainment(proof); err != nil {
		return err
	} else if verified {
		return nil
	}
	completion, err := readRetryPrivate(filepath.Join(proof.Fence.JobDirectory, "execution-completion.json"))
	if err != nil {
		return err
	}
	receipt := verifiedContainmentReceipt{proof, executionHash(completion)}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	// Publish complete bytes with no overwrite. A kill during write must leave
	// only an unreferenced temporary file, never a partial authoritative receipt.
	file, err := os.CreateTemp(proof.Fence.JobDirectory, ".execution-drain-")
	if err != nil {
		return err
	}
	name := file.Name()
	defer os.Remove(name) //nolint:errcheck
	if _, err = file.Write(raw); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	target := filepath.Join(proof.Fence.JobDirectory, "execution-drain-"+proof.Fence.Generation+".json")
	if err = os.Link(name, target); os.IsExist(err) {
		if verified, e := verifiedContainment(proof); e != nil {
			return e
		} else if !verified {
			return ErrExecutionFenced
		}
	} else if err != nil {
		return err
	}
	return syncDirectory(proof.Fence.JobDirectory)
}
func reconcileExecutionContainment(fence ExecutionFence) error {
	proof, err := readContainmentProof(fence)
	if os.IsNotExist(err) && executionNamespaceFixture() {
		return nil
	}
	if err != nil {
		return ErrExecutionFenced
	}
	// A committed drain receipt authenticates the old generation's quiescence,
	// even after a crash before fence unlink and a supervisor restart. It binds
	// the exact raw completion, not a new operation or authority to dispatch.
	if verified, e := verifiedContainment(proof); e != nil {
		return ErrExecutionFenced
	} else if verified {
		return nil
	}

	if err = verifyContainmentProof(proof); err != nil {
		return err
	}
	return persistVerifiedContainment(proof)
}

var observeContainmentProcess = readContainmentProcess
var observeContainmentMembers = containmentMembers

func containmentMembers(unit string) ([]int, error) {
	var members []int
	values, err := observeContainmentUnit(unit)
	if err != nil {
		return nil, err
	}
	group, err := executionUnitGroup(unit, values["ControlGroup"])
	if err != nil {
		return nil, err
	}
	err = filepath.WalkDir(filepath.Join("/sys/fs/cgroup", group), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Name() != "cgroup.procs" {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, field := range strings.Fields(string(raw)) {
			pid, err := strconv.Atoi(field)
			if err != nil {
				return err
			}
			members = append(members, pid)
		}
		return nil
	})
	return members, err
}

func reconcileControllerExecution(fence ExecutionFence, runErr error) error {
	// Do not turn a failed drain into an automatic second observation. An
	// explicit later reconciliation may obtain new authoritative evidence.
	if errors.Is(runErr, errExecutionContainmentStopUnverified) {
		return ErrExecutionFenced
	}
	return ReconcileExecutionFence(fence)
}
