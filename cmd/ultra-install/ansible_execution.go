package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type frozenExecution struct {
	Schema            int    `json:"schema_version"`
	Native            bool   `json:"native_adoption,omitempty"`
	NativeMachineSHA  string `json:"native_machine_sha256,omitempty"`
	Target            string `json:"target"`
	Local             bool   `json:"local"`
	LockDirectory     string `json:"lock_directory"`
	OperatorDirectory string `json:"operator_lock_directory,omitempty"`
	BootstrapEngine   string `json:"bootstrap_engine,omitempty"`
}

// The attempt journal always lives at the same operator location, irrespective
// of whether broker installation later makes local execution possible.
func bootstrapStateRoot() (string, error) {
	path := os.Getenv("ULTRA_INSTALL_STATE_DIR")
	if path == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(cache, "ultra-install")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if err = ensurePrivateBootstrapDirectory(path); err != nil {
		return "", err
	}
	return path, nil
}

func withBootstrapOperatorLock(ctx context.Context, stateRoot string) (context.Context, func(), error) {
	directory := filepath.Join(stateRoot, "operator")
	if err := ensurePrivateBootstrapDirectory(directory); err != nil {
		return ctx, nil, err
	}
	return deployansible.WithOperationLock(ctx, directory)
}

func freezeBootstrapExecution(p *installplan.InstallPlan, directory, stateRoot string) (string, error) {
	return freezeBootstrapExecutionWith(p, directory, stateRoot, attestNativeAdoption)
}

func freezeBootstrapExecutionWith(
	p *installplan.InstallPlan,
	directory, stateRoot string,
	attest func(*installplan.InstallPlan) (string, error),
) (string, error) {
	path := filepath.Join(directory, "execution-mode.json")
	target := p.Bridge.SSHHost + "|" + p.Bridge.Address
	var frozen frozenExecution
	nativeMachine := ""
	if p.BridgeNative {
		var err error
		nativeMachine, err = attest(p)
		if err != nil {
			return "", err
		}
	}
	if info, err := os.Lstat(path); err == nil {
		owner, okay := info.Sys().(*syscall.Stat_t)
		if !okay || owner.Uid != uint32(os.Geteuid()) || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 4096 {
			return "", errors.New("private frozen execution required")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if json.Unmarshal(raw, &frozen) != nil || frozen.Schema != 1 || frozen.Target != target {
			return "", errors.New("frozen execution target changed")
		}
		if frozen.Native != p.BridgeNative || frozen.NativeMachineSHA != nativeMachine || (frozen.Native && frozen.Local) {
			return "", errors.New("frozen native execution identity changed")
		}
		if frozen.BootstrapEngine != "" && frozen.BootstrapEngine != "components-v1" {
			return "", errors.New("frozen bootstrap engine unsupported")
		}
		expected := stateRoot
		if frozen.Local {
			expected = "/var/lib/ultra-ansible"
		}
		if frozen.LockDirectory != expected {
			return "", errors.New("frozen execution lock changed")
		}
		if frozen.OperatorDirectory != "" && frozen.OperatorDirectory != filepath.Join(stateRoot, "operator") {
			return "", errors.New("frozen execution operator lock changed")
		}
		if frozen.Local && !localLifecycleMachineIdentity(p) {
			return "", errors.New("frozen local target identity changed")
		}
	} else if os.IsNotExist(err) {
		local := localLifecycleBridge(p)
		lock := stateRoot
		if local {
			lock = "/var/lib/ultra-ansible"
		}
		frozen = frozenExecution{Schema: 1, Native: p.BridgeNative, NativeMachineSHA: nativeMachine, Target: target, Local: local, LockDirectory: lock, OperatorDirectory: filepath.Join(stateRoot, "operator"), BootstrapEngine: "components-v1"}
		raw, err := json.Marshal(frozen)
		if err != nil {
			return "", err
		}
		if err = writeBootstrapFrozenFile(path, raw); err != nil {
			return "", err
		}
	} else {
		return "", err
	}
	local := frozen.Local
	p.ControllerLocal = &local
	p.ControllerLocalTarget = target
	if err := ensurePrivateBootstrapDirectory(frozen.LockDirectory); err != nil {
		return "", err
	}
	return frozen.LockDirectory, nil
}
func writeBootstrapFrozenFile(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".execution-")
	if err != nil {
		return err
	}
	temporary := f.Name()
	defer os.Remove(temporary) //nolint:errcheck
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(raw)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Link(temporary, path); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close() //nolint:errcheck
	return parent.Sync()
}

func withFrozenLifecycleLock(
	ctx context.Context,
	p *installplan.InstallPlan,
	lockDirectory, directory string,
) (context.Context, func(), error) {
	if !localLifecycleBridge(p) {
		return deployansible.WithOperationLock(ctx, lockDirectory)
	}
	socket := os.Getenv("ULTRA_ANSIBLE_SOCKET")
	if socket == "" {
		socket = "/run/ultra-ansible/controller.sock"
	}
	return (deployansible.Client{Socket: socket}).WithLifecycleOperationLock(ctx, lockDirectory, lifecycleID(directory))
}
