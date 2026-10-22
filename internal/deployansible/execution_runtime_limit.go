package deployansible

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
)

var errExecutionRuntimeLimit = errors.New("execution_runtime_limit")

// observeExecutionRuntimeLimit retains the manager's timeout fact before failed
// transient-unit collection. It intentionally creates neither completion nor
// drain evidence, and never changes a receipt written by the controller.
func savedExecutionRuntimeLimit(fence ExecutionFence) error {
	for _, prefix := range []string{"execution-runtime-limit-", "execution-systemd-limit-"} {
		raw, err := readRetryPrivate(filepath.Join(fence.JobDirectory, prefix+fence.Generation+".json"))
		if os.IsNotExist(err) {
			continue
		}
		var saved struct {
			Fence      ExecutionFence `json:"fence"`
			Diagnostic Diagnostic     `json:"diagnostic"`
		}
		if err != nil || json.Unmarshal(raw, &saved) != nil || saved.Fence != fence || saved.Diagnostic.Code != "execution_runtime_limit" {
			return ErrExecutionFenced
		}
		return errExecutionRuntimeLimit
	}
	return nil
}

func observeExecutionRuntimeLimit(fence ExecutionFence) error {
	if err := savedExecutionRuntimeLimit(fence); err != nil {
		return err
	}
	if executionFenceDirectory(fence.JobDirectory) != "/var/lib/ultra-ansible" {
		return nil
	}
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(fence.Generation) {
		return ErrExecutionFenced
	}
	unit := "ultra-execution-" + fence.Generation + ".service"
	values, err := observeContainmentUnit(unit)
	if err != nil {
		return nil
	} // Missing manager evidence cannot establish a timeout.
	if values["Result"] != "timeout" || values["LoadState"] != "loaded" ||
		!regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(values["InvocationID"]) {
		return nil
	}
	binding, err := executionBinding(fence.JobDirectory)
	if err != nil {
		return ErrExecutionFenced
	}
	binding.Generation = fence.Generation
	if binding != fence {
		return ErrExecutionFenced
	}
	value := struct {
		Schema       int            `json:"schema"`
		Fence        ExecutionFence `json:"fence"`
		Unit         string         `json:"unit"`
		InvocationID string         `json:"invocation_id"`
		Result       string         `json:"result"`
		Diagnostic   Diagnostic     `json:"diagnostic"`
	}{1, fence, unit, values["InvocationID"], "timeout", Diagnostic{Stage: "execute", Node: "local", Code: "execution_runtime_limit"}}
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	// The systemd observer and controller can report distinct timeout facts;
	// separate names avoid overwriting either independently authenticated source.
	target := filepath.Join(fence.JobDirectory, "execution-systemd-limit-"+fence.Generation+".json")
	if prior, readErr := readRetryPrivate(target); readErr == nil {
		if string(prior) != string(raw) {
			return ErrExecutionFenced
		}
		return errExecutionRuntimeLimit
	} else if !os.IsNotExist(readErr) {
		return readErr
	}
	file, err := os.CreateTemp(fence.JobDirectory, ".execution-limit-")
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
	if err = os.Link(name, target); err != nil {
		return err
	}
	if err = syncDirectory(fence.JobDirectory); err != nil {
		return err
	}
	return errExecutionRuntimeLimit
}
