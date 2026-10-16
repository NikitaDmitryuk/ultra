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
)

type operationLeaseKey struct{}
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
	if lease, ok := ctx.Value(operationLeaseKey{}).(*operationLease); ok {
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
