package deployansible

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// The operation record excludes other dispatchers between individual Ansible
// generations too, including a foreground reconcile with remote SSH children.
// An expired client, idle flock or stopped supervisor never opens this gate.
func deploymentExecutionAdmission(root string) error {
	cgroup, _ := os.ReadFile("/proc/self/cgroup")
	return checkDeploymentExecutionAdmission(root, cgroup)
}

func checkDeploymentExecutionAdmission(root string, cgroup []byte) error {
	directory := filepath.Join(root, "deploy-operations")
	info, err := os.Lstat(directory)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
		return ErrExecutionFenced
	}
	raw, err := readRetryPrivate(filepath.Join(directory, "current.json"))
	if os.IsNotExist(err) {
		return nil
	}
	var current struct {
		Schema  int    `json:"schema"`
		Request string `json:"request_sha256"`
	}
	if err != nil || json.Unmarshal(raw, &current) != nil || current.Schema != 1 ||
		len(current.Request) != 64 || strings.Trim(current.Request, "0123456789abcdef") != "" {
		return ErrExecutionFenced
	}
	operation := filepath.Join(directory, current.Request)
	for _, path := range []string{directory, operation} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || !ownedByProcess(info) || info.Mode().Perm()&0077 != 0 {
			return ErrExecutionFenced
		}
	}
	raw, err = readRetryPrivate(filepath.Join(operation, "request.json"))
	if err != nil || executionHash(raw) != current.Request {
		return ErrExecutionFenced
	}
	raw, err = readRetryPrivate(filepath.Join(operation, "state.json"))
	var state struct {
		Schema  int    `json:"schema"`
		Request string `json:"request_sha256"`
		Stage   string `json:"stage"`
		State   string `json:"state"`
	}
	if err != nil || json.Unmarshal(raw, &state) != nil || state.Schema != 1 || state.Request != current.Request || state.Stage == "" {
		return ErrExecutionFenced
	}
	if state.State == "completed" && state.Stage == "status" {
		return nil
	}
	if state.State != "running" {
		return ErrExecutionFenced
	}
	unit := ":/system.slice/ultra-deploy-" + current.Request + ".service"
	for _, line := range strings.Split(string(cgroup), "\n") {
		if strings.HasSuffix(line, unit) {
			return nil
		}
	}
	return ErrExecutionFenced
}
