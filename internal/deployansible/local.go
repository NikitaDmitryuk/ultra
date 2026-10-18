package deployansible

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type operationLeaseKey struct{}
type readinessProbeKey struct{}
type operationLease struct {
	directory string
	file      *os.File
	active    atomic.Bool
	run       sync.Mutex
}

// WithOperationLock holds one lease across inspection, application and verification.
// Callers must pass the returned context to every RunLocal stage.
func WithOperationLock(ctx context.Context, directory string) (context.Context, func(), error) {
	if !filepath.IsAbs(directory) {
		return ctx, nil, errors.New("absolute operation lock directory required")
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
		return ctx, nil, errors.New("private operation lock directory required")
	}
	lock, err := controllerLock(filepath.Join(directory, "infrastructure.lock"))
	if err != nil {
		return ctx, nil, err
	}
	lease := &operationLease{directory: directory, file: lock}
	lease.active.Store(true)
	return context.WithValue(ctx, operationLeaseKey{}, lease), func() {
		lease.run.Lock()
		defer lease.run.Unlock()
		if lease.active.Swap(false) {
			_ = lock.Close()
		}
	}, nil
}

// RunLocal runs an operator-owned, fixed operation. It is deliberately unavailable
// through the relay socket: inventory and source paths are trusted operator inputs.
// Reusing a directory resumes exactly the same frozen inputs after interruption.
func RunLocal(
	ctx context.Context,
	operation string,
	inventory, variables map[string]any,
	directory, python, executable string,
) (Receipt, error) {
	return runLocal(ctx, operation, inventory, variables, directory, python, executable, false, "")
}

// WaitUpgradeReadiness is the sole unlocked operation. Its fixed playbook reads
// recovery evidence and the protected lifecycle journal only. The caller must
// still inspect under its lease.
// Temporary observations are never reused as upgrade authorization or receipts.
func WaitUpgradeReadiness(
	ctx context.Context,
	inventory map[string]any,
	lockDirectory, python, executable, lifecycleID string,
	pending bool,
	diagnosticDirectory string,
) error {
	if !jobID.MatchString(lifecycleID) {
		return errors.New("invalid_readiness_lifecycle_id")
	}
	if _, leased := ctx.Value(operationLeaseKey{}).(*operationLease); leased {
		return errors.New("readiness_probe_requires_unleased_context")
	}
	ctx, cancel := context.WithTimeout(ctx, 780*time.Second)
	defer cancel()
	ctx = context.WithValue(ctx, readinessProbeKey{}, true)
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		temporary, err := os.MkdirTemp("", "ultra-readiness-")
		if err != nil {
			return err
		}
		receipt, runErr := RunLocal(ctx, "wait-upgrade-readiness", inventory,
			map[string]any{
				"ultra_lock_directory":                lockDirectory,
				"ultra_readiness_lifecycle_id":        lifecycleID,
				"ultra_readiness_reservation_pending": pending,
			}, filepath.Join(temporary, "probe"), python, executable)
		_ = os.RemoveAll(temporary)
		if err := ctx.Err(); err != nil {
			return err
		}
		if runErr != nil {
			lastErr = runErr
			if diagnosticDirectory != "" {
				if diagnosticErr := persistReadinessDiagnostic(diagnosticDirectory, receipt.Diagnostic); diagnosticErr != nil {
					return errors.Join(runErr, errors.New("readiness_diagnostic_persist_failed"))
				}
			}
			if !transientSSHDiagnostic(receipt.Diagnostic.Code) || attempt == 2 {
				return runErr
			}
		} else {
			if receipt.Result.Values["verified"] != true || ((pending || receipt.Result.Values["ready"] != true) &&
				(receipt.Result.Values["reservation_id"] != lifecycleID || receipt.Result.Values["reservation_phase"] != "applying")) {
				return errors.New("upgrade_readiness_probe_unverified")
			}
			return nil
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return lastErr
}

func transientSSHDiagnostic(code string) bool {
	switch code {
	case "ssh_banner_timeout", "ssh_connect_timeout", "ssh_connection_reset":
		return true
	}
	return false
}

// persistReadinessDiagnostic retains only the fixed callback fields after a
// failed temporary readiness probe. The request, inventory, result, and raw
// Ansible output remain private and are still removed with the probe directory.
func persistReadinessDiagnostic(directory string, diagnostic Diagnostic) error {
	if diagnostic.Code == "" || diagnostic.Stage == "" || diagnostic.Node == "" ||
		len(diagnostic.Code) > 64 || len(diagnostic.Stage) > 160 || len(diagnostic.Node) > 128 {
		return nil
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
		return errors.New("private readiness diagnostic directory required")
	}
	raw, err := json.Marshal(diagnostic)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, fmt.Sprintf("readiness-diagnostic-%d.json", time.Now().UnixNano()))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
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
	directoryFile, err := os.Open(directory)
	if err != nil {
		return err
	}
	defer directoryFile.Close() //nolint:errcheck
	return directoryFile.Sync()
}

// RunLocalRetryFailed is an explicit operator retry. Successful cached stages stay
// cached; terminal failures are archived before a new attempt can execute.
// It is not used by typed workers or automatic upgrades.
func RunLocalRetryFailed(
	ctx context.Context,
	operation string,
	inventory, variables map[string]any,
	directory, python, executable string,
) (Receipt, error) {
	if !localRetryOperation(operation, variables) {
		return Receipt{}, errors.New("retry_bootstrap_operation_required")
	}
	if _, ok := ctx.Value(operationLeaseKey{}).(*operationLease); !ok {
		return Receipt{}, errors.New("retry requires operation lease")
	}
	return runLocal(ctx, operation, inventory, variables, directory, python, executable, true, "")
}

func localRetryOperation(operation string, variables map[string]any) bool {
	if operation == "ingress" {
		switch variables["ultra_ingress_action"] {
		case "prepare", "activate", "adopt", "retire-experiment":
			return true
		default:
			return false
		}
	}
	if bootstrapRetryOperation(operation) {
		return true
	}
	switch operation {
	case "upgrade-runtime":
		switch variables["ultra_runtime_action"] {
		case "prepare", "commit", "rollback":
			return true
		case "tls-release":
			requests, ok := variables["ultra_managed_tunnel_requests"].(map[string]string)
			hook, hookOK := variables["ultra_managed_tunnel_hook_sha256"].(string)
			decoded, err := hex.DecodeString(hook)
			return ok && len(requests) == 1 && hookOK && err == nil && len(decoded) == sha256.Size
		}
	case "upgrade-domain":
		switch variables["ultra_upgrade_domain_action"] {
		case "apply", "accept", "rollback", "retire", "finalize":
			return true
		}
	case "upgrade-dns-migration":
		switch variables["ultra_dns_migration_action"] {
		case "prepare", "promote", "retire", "rollback":
			return true
		}
	case "rollback":
		inputs, ok := variables["ultra_runtime_effect_inputs"].(map[string]string)
		return ok && len(inputs) > 0
	}
	return false
}

func runLocal(
	ctx context.Context,
	operation string,
	inventory, variables map[string]any,
	directory, python, executable string,
	retry bool,
	source string,
) (Receipt, error) {
	allowed := map[string]bool{
		"bootstrap-recovery-inspect":   true,
		"bootstrap-recovery-tools":     true,
		"wait-upgrade-readiness":       true,
		"bootstrap-forward-broker":     true,
		"contain-upgrade":              true,
		"drain-upgrade-workers":        true,
		"retain-artifacts":             true,
		"resume-schedules":             true,
		"rollback-adoption":            true,
		"reserve-rolledback-bootstrap": true,
		"resume-adoption":              true,
		"lifecycle":                    true,
		"prepare-controller":           true,
		"inspect-bootstrap":            true,
		"inspect-upgrade":              true,
		"preflight-retry":              true,
		"status-automation":            true,
		"inspect-release-hosts":        true,
		"resume-automation":            true,
		"configure-bot":                true,
		"configure-exit-operator":      true,
		"ingress":                      true,
		"bootstrap":                    true,
		"bootstrap-postgres":           true,
		"bootstrap-exit":               true,
		"bootstrap-bridge":             true,
		"bootstrap-automation":         true,
		"verify-bootstrap-automation":  true,
		"adopt":                        true,
		"adopt-topology":               true,
		"upgrade":                      true,
		"rollback":                     true,
		"reconcile":                    true,
		"restore":                      true,
		"restore-database":             true,
		"restore-peer":                 true,
		"verify-release":               true,
		"commit-release":               true,
		"publish-release":              true,
		"domain-cutover":               true,
		"backend-domain":               true,
		"upgrade-dns-migration":        true,
		"inspect-upgrade-runtime":      true,
		"inspect-upgrade-maintenance":  true,
		"upgrade-runtime":              true,
		"inspect-upgrade-domains":      true,
		"upgrade-domain":               true,
	}
	if !allowed[operation] || !filepath.IsAbs(directory) || !filepath.IsAbs(python) || !filepath.IsAbs(executable) {
		return Receipt{}, errors.New("invalid local operation or executor paths")
	}
	parent := filepath.Dir(directory)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return Receipt{}, err
	}
	lockDirectory := parent
	if lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease); ok {
		lockDirectory = lease.directory
	}
	if configured, ok := variables["ultra_lock_directory"].(string); ok {
		if !filepath.IsAbs(configured) {
			return Receipt{}, errors.New("absolute operation lock directory required")
		}
		lockDirectory = configured
	}
	lockInfo, err := os.Lstat(lockDirectory)
	if err != nil || !lockInfo.IsDir() || !ownedByProcess(lockInfo) || lockInfo.Mode().Perm()&0077 != 0 {
		return Receipt{}, errors.New("private operation lock directory required")
	}
	unlocked, _ := ctx.Value(readinessProbeKey{}).(bool)
	if operation == "wait-upgrade-readiness" && !unlocked {
		return Receipt{}, errors.New("readiness_probe_requires_dedicated_entrypoint")
	}
	if unlocked && (operation != "wait-upgrade-readiness" || retry || source != "") {
		return Receipt{}, errors.New("invalid_unlocked_readiness_probe")
	}
	if unlocked {
		if _, leased := ctx.Value(operationLeaseKey{}).(*operationLease); leased {
			return Receipt{}, errors.New("readiness_probe_requires_unleased_context")
		}
	} else if lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease); ok {
		lease.run.Lock()
		defer lease.run.Unlock()
		if !lease.active.Load() || lease.directory != lockDirectory {
			return Receipt{}, errors.New("operation lease directory mismatch")
		}
	} else {
		lock, err := controllerLock(filepath.Join(lockDirectory, "infrastructure.lock"))
		if err != nil {
			return Receipt{}, err
		}
		defer lock.Close() //nolint:errcheck
	}
	raw, err := json.Marshal(map[string]any{"inventory": inventory, "variables": variables})
	if err != nil {
		return Receipt{}, err
	}

	// codeql[go/weak-sensitive-data-hashing] This deterministic digest binds a frozen operation request for idempotency; it is not used to authenticate a password or stored as a credential verifier.
	hash := sha256.Sum256(raw)
	id := hex.EncodeToString(hash[:])
	export := Export
	if source != "" {
		export, err = pinnedBootstrapExporter(source, directory, operation, raw)
		if err != nil {
			return Receipt{}, err
		}
	}
	if receipt, cached, cacheErr := collectedRetentionResult(operation, directory, raw, id); cached {
		return receipt, cacheErr
	}
	if err = prepareLocalOperation(directory, operation, raw, id, export); err != nil {
		return Receipt{}, err
	}
	if retry {
		if err = retryFailedLocalAttempt(directory); err != nil {
			return Receipt{}, err
		}
	}
	bundle := filepath.Join(directory, "bundle")
	command := exec.CommandContext(
		ctx,
		python,
		filepath.Join(bundle, "controller.py"),
		"--job",
		directory,
		"--bundle",
		bundle,
		"--executable",
		executable,
	)
	isolateCommand(command)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	runErr := command.Run()
	data, err := os.ReadFile(filepath.Join(directory, "receipt.json"))
	var receipt Receipt
	if err != nil || json.Unmarshal(data, &receipt) != nil {
		return Receipt{}, errors.New("local operation receipt unavailable")
	}
	if runErr != nil || receipt.State != "succeeded" {
		return receipt, fmt.Errorf("ansible operation failed: %s", receipt.Code)
	}
	return receipt, nil
}
