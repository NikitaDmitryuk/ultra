package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// One producer for schema1 and schema2: direct child of the sole supervisor,
// after its infrastructure OFD closes. Unknown child completion is never replayed.
func runDeployPostActivationReconcile(ctx context.Context, args []string) error {
	envelope, identity, operation, err := runningDeployReconcileRequest()
	if err != nil {
		return err
	}
	if envelope == nil {
		return errors.New("deploy_post_activation_supervisor_required")
	}
	cleaned, _ := cleanDeployRetry(args)
	a, _ := json.Marshal(cleaned)
	b, _ := json.Marshal(envelope.Args)
	if string(a) != string(b) {
		return errors.New("deploy_post_activation_arguments_changed")
	}
	if got, e := deployOperationIdentity(*envelope, "/proc/self/exe"); e != nil || got != identity {
		return errors.New("deploy_post_activation_candidate_changed")
	}
	flags := map[string]string{}
	for i := 1; i < len(envelope.Args); i++ {
		key := envelope.Args[i]
		if key == "--lifecycle" || key == "--forward-only" {
			continue
		}
		i++
		flags[key] = envelope.Args[i]
	}
	directory := flags["--job-dir"]
	if directory == "" {
		directory = filepath.Join("/var/lib/ultra-ansible", "upgrade-"+flags["--version"])
	}
	p, e := installplan.LoadConfig(flags["--config"])
	if e != nil || matchOperatorPlan(directory, p, flags["--release-dir"]) != nil {
		return errors.New("deploy_post_activation_plan_changed")
	}
	watermark, err := recoveryActivationWatermark(directory)
	if err != nil {
		return err
	}
	active, e := readRebuildInput("/opt/ultra-recovery/release-manifest.json", true)
	if e != nil || digestSHA256(active) != flags["--manifest-sha256"] {
		return errors.New("deploy_post_activation_candidate_manifest_required")
	}
	_, freshnessError := readDeployPostActivationReadiness(ctx, watermark)
	fresh := freshnessError == nil
	if envelope.Preparation != nil {
		fresh = fresh && verifyRecoveryRestoredSchedules(ctx, *envelope.Preparation) == nil
	}
	if fence, e := deployansible.InspectExecutionFence(); e != nil || fence != nil {
		return errors.New("deploy_post_activation_execution_uncertain")
	}
	lock, e := os.OpenFile("/var/lib/ultra-ansible/infrastructure.lock", os.O_RDWR|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return e
	}
	e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if e == nil {
		e = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	}
	_ = lock.Close()
	if e != nil {
		return errors.New("deploy_post_activation_infrastructure_lease_held")
	}
	for attempt := 1; attempt <= 1000; attempt++ {
		path := filepath.Join(operation, fmt.Sprintf("post-activation-%d", attempt))
		complete, e := completedDeployPostActivationAttempt(identity, path, watermark)
		if e != nil {
			return e
		}
		if complete {
			continue
		}
		if fresh && attempt > 1 {
			return nil
		}
		started := time.Now().Unix()
		intent, _ := json.Marshal(map[string]any{"request_sha256": identity, "watermark": watermark, "started_at": started})
		if err = publishRetainedReconcile(path+".started.json", intent); err != nil {
			return err
		}
		command := exec.CommandContext(
			ctx,
			"/usr/bin/python3",
			"/opt/ultra-recovery/reconcile.py",
			"--config",
			"/etc/ultra-recovery/reconcile.json",
			"--deployment",
			identity,
			"--terminal",
			path+".json",
			"--started-at",
			fmt.Sprint(started),
			"--not-before",
			fmt.Sprint(watermark),
		)
		if command.Run() != nil {
			return errors.New("deploy_post_activation_reconcile_uncertain")
		}
		if _, err = completedDeployPostActivationAttempt(identity, path, watermark); err != nil {
			return err
		}
		if _, err = readDeployPostActivationReadiness(ctx, watermark); err != nil {
			return err
		}
		if envelope.Preparation != nil {
			return verifyRecoveryRestoredSchedules(ctx, *envelope.Preparation)
		}
		return nil
	}
	return errors.New("deploy_post_activation_attempt_limit")
}

func readDeployPostActivationReadiness(ctx context.Context, watermark int64) (map[string]any, error) {
	output, err := exec.CommandContext(ctx, "/usr/bin/python3", "/opt/ultra-recovery/recovery_status.py", "--not-before", fmt.Sprint(watermark)).
		Output()
	if err != nil {
		return nil, errors.New("fresh_independent_backup_required")
	}
	return validateRecoveryPreparationReadiness(output)
}

func runningDeployReconcileRequest() (*deployOperationRequest, string, string, error) {
	path := filepath.Join(deployOperationsRoot, "current.json")
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil, "", "", nil
	} else if err != nil {
		return nil, "", "", err
	}
	raw, err := readRebuildInput(path, true)
	var pointer struct {
		Schema  int    `json:"schema"`
		Request string `json:"request_sha256"`
	}
	fail := errors.New("deploy_post_activation_supervisor_unverified")
	if err != nil || json.Unmarshal(raw, &pointer) != nil || pointer.Schema != 1 || !runtimeHostValidDigest(pointer.Request) {
		return nil, "", "", fail
	}
	directory := filepath.Join(deployOperationsRoot, pointer.Request)
	raw, err = readRebuildInput(filepath.Join(directory, "request.json"), true)
	var envelope deployOperationRequest
	if err != nil || digestSHA256(raw) != pointer.Request || decodeRetainedReconcile(raw, &envelope) != nil ||
		(envelope.Schema != 1 && envelope.Schema != 2) ||
		(envelope.Schema == 2) != (envelope.Preparation != nil) {
		return nil, "", "", fail
	}
	state, err := readDeployOperation(directory, envelope)
	if err != nil {
		return nil, "", "", err
	}
	if state.State == "completed" && state.Stage == "status" {
		return nil, "", "", nil
	}
	if state.State != "running" || (state.Stage != "upgrade" && state.Stage != "status") {
		return nil, "", "", fail
	}
	cgroup, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return nil, "", "", err
	}
	for _, line := range strings.Split(string(cgroup), "\n") {
		if strings.HasSuffix(line, ":/system.slice/ultra-deploy-"+pointer.Request+".service") {
			return &envelope, pointer.Request, directory, nil
		}
	}
	return nil, "", "", fail
}

func completedDeployPostActivationAttempt(identity, path string, watermark int64) (bool, error) {
	raw, err := readOptionalRecoveryPrivate(path + ".started.json")
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var intent struct {
		Request   string `json:"request_sha256"`
		Watermark int64  `json:"watermark"`
		Started   int64  `json:"started_at"`
	}
	if json.Unmarshal(raw, &intent) != nil || intent.Request != identity || intent.Watermark > watermark || intent.Started <= 0 {
		return false, errors.New("recovery_post_activation_intent_changed")
	}
	terminal, err := readRebuildInput(path+".json", true)
	var proof struct {
		Protocol string `json:"protocol"`
		Request  string `json:"request_sha256"`
		Phase    string `json:"phase"`
		Started  int64  `json:"started_at"`
		Verified bool   `json:"verified"`
	}
	if err != nil || json.Unmarshal(terminal, &proof) != nil || proof.Protocol != "ultra-deploy-post-activation-v1" ||
		proof.Request != identity ||
		proof.Phase != "post_activation_reconciled" ||
		proof.Started != intent.Started ||
		!proof.Verified {
		return false, errors.New("recovery_post_activation_reconcile_uncertain")
	}
	return true, nil
}

// Preserve optional-path absence before the privacy-safe reader deliberately
// classifies unsafe/unreadable paths with a single non-disclosing error.
func readOptionalRecoveryPrivate(path string) ([]byte, error) {
	if _, err := os.Lstat(path); err != nil {
		return nil, err
	}
	return readRebuildInput(path, true)
}

func recoveryActivationWatermark(directory string) (int64, error) {
	job := filepath.Join(directory, "activate")
	receiptRaw, err := readRebuildInput(filepath.Join(job, "receipt.json"), true)
	var receipt deployansible.Receipt
	if err != nil || json.Unmarshal(receiptRaw, &receipt) != nil || receipt.State != "succeeded" {
		return 0, errors.New("recovery_post_activation_completion_unproven")
	}
	completeRaw, err := readRebuildInput(filepath.Join(job, "execution-completion.json"), true)
	var complete struct {
		Outcome string                       `json:"outcome"`
		Cleanup bool                         `json:"local_cleanup"`
		Receipt string                       `json:"receipt_sha256"`
		Fence   deployansible.ExecutionFence `json:"fence"`
	}
	jobRaw, e := readRebuildInput(filepath.Join(job, "job.json"), true)
	requestRaw, re := readRebuildInput(filepath.Join(job, "request.json"), true)
	if err != nil || e != nil || re != nil || json.Unmarshal(completeRaw, &complete) != nil || complete.Outcome != "succeeded" ||
		!complete.Cleanup ||
		complete.Receipt != digestSHA256(receiptRaw) ||
		complete.Fence.JobDirectory != job ||
		complete.Fence.Operation != "upgrade" ||
		complete.Fence.JobSHA256 != digestSHA256(jobRaw) ||
		complete.Fence.RequestSHA256 != digestSHA256(requestRaw) {
		return 0, errors.New("recovery_post_activation_completion_unproven")
	}
	return activationTimestamp(receipt.Result.Values["activated_at"])
}

func verifyRecoveryRestoredSchedules(ctx context.Context, r recoveryPreparationRequest) error {
	source, err := ansibleassets.Bundle.ReadFile("library/ultra_controller_enforcement.py")
	if err != nil {
		return err
	}
	program := "import sys\n__name__='recovery_schedule_observer'\n" + string(source) + `
r=json.loads(sys.argv[1]);need(prepared_schedules_restored(r,sys.argv[2]))
for name in ['ultra-recovery-backup.timer','ultra-recovery-reconcile.timer']:
 values=dict(line.split('=',1) for line in subprocess.run(['systemctl','show','--property=ActiveState','--property=UnitFileState',name],check=True,stdout=subprocess.PIPE,timeout=10).stdout.decode().splitlines() if '=' in line)
 need(values.get('ActiveState')=='active' and values.get('UnitFileState')=='enabled')
`
	raw, _ := json.Marshal(r)
	if exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", program, string(raw), r.digest()).Run() != nil {
		return errors.New("recovery_post_activation_schedule_checkpoint_required")
	}
	return nil
}
