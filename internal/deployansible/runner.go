// Package deployansible prepares private inputs for versioned Ansible operations.
package deployansible

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	"github.com/NikitaDmitryuk/ultra/internal/config"
)

// ExitRequest carries a pinned artifact and existing route identity, never generates UUIDs.
type ExitRequest struct {
	ExecutionTimeoutSeconds int64       `json:"execution_timeout_seconds,omitempty"`
	Port                    int         `json:"port,omitempty"`
	Host                    string      `json:"host"`
	User                    string      `json:"user"`
	Identity                string      `json:"identity"`
	KnownHosts              string      `json:"known_hosts"`
	BridgeIPv4              string      `json:"bridge_ipv4"`
	Spec                    config.Spec `json:"spec"`
}

type Result struct {
	CertPin string         `json:"cert_pin"`
	Values  map[string]any `json:"-"`
}

func (r *Result) UnmarshalJSON(data []byte) error {
	var values map[string]any
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	r.Values = values
	r.CertPin, _ = values["cert_pin"].(string)
	return nil
}

type Diagnostic struct {
	Stage string `json:"stage"`
	Node  string `json:"node"`
	Code  string `json:"code"`
}

type Receipt struct {
	Diagnostic    Diagnostic `json:"diagnostic,omitempty"`
	State         string     `json:"state"`
	Code          string     `json:"code,omitempty"`
	RequestSHA256 string     `json:"request_sha256"`
	BinarySHA256  string     `json:"binary_sha256"`
	Result        Result     `json:"result"`
}

// Export writes only embedded source into a private versioned workspace.
func Export(directory string) error {
	return fs.WalkDir(ansibleassets.Bundle, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(directory, filepath.FromSlash(name))
		if d.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		data, err := ansibleassets.Bundle.ReadFile(name)
		if err != nil {
			return err
		}
		return writePrivate(target, data)
	})
}

func (r ExitRequest) validatePolicy() error {
	if r.ExecutionTimeoutSeconds < 0 || r.ExecutionTimeoutSeconds > 9223371976 {
		return errors.New("invalid_execution_timeout")
	}
	if r.Port < 0 || r.Port > 65535 {
		return errors.New("invalid SSH port")
	}
	if net.ParseIP(r.Host) == nil || net.ParseIP(r.BridgeIPv4).To4() == nil ||
		!regexp.MustCompile(`^[a-z_][a-z0-9_-]*$`).MatchString(r.User) {
		return errors.New("invalid Ansible exit target")
	}
	if !filepath.IsAbs(r.Identity) || !filepath.IsAbs(r.KnownHosts) {
		return errors.New("absolute SSH identity and pins required")
	}
	if r.Spec.Role != config.RoleExit {
		return errors.New("exit specification required")
	}
	return r.Spec.Validate()
}

func (r ExitRequest) Validate() error {
	if err := r.validatePolicy(); err != nil {
		return err
	}
	info, err := os.Lstat(r.KnownHosts)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || (info.Size() == 0 || info.Size() > 1<<20) {
		return errors.New("verified SSH pins required")
	}
	identity, err := os.Lstat(r.Identity)
	if err != nil || !identity.Mode().IsRegular() || identity.Mode().Perm()&0077 != 0 || identity.Size() == 0 || identity.Size() > 65536 {
		return errors.New("private SSH identity required")
	}
	return nil
}

// Prepare fixes all inputs before execution; the directory must not already exist.
func Prepare(directory, binary string, request ExitRequest) error {
	inputs, err := openInputs(binary, request)
	if err != nil {
		return err
	}
	defer closeInputs(inputs)
	return prepareInputs(directory, binary, request, inputs)
}

func prepareInputs(directory, binary string, request ExitRequest, inputs []*os.File) error {
	if err := request.validatePolicy(); err != nil {
		return err
	}
	if len(inputs) != 3 {
		return errors.New("three submitted inputs required")
	}
	if !filepath.IsAbs(binary) {
		return errors.New("absolute pinned binary required")
	}
	if !filepath.IsAbs(directory) {
		return errors.New("absolute job directory required")
	}
	if err := os.Mkdir(directory, 0700); err != nil {
		return err
	}
	preparationLock, err := controllerLock(filepath.Join(directory, "execution.lock"))
	if err != nil {
		_ = os.RemoveAll(directory)
		return err
	}
	defer preparationLock.Close() //nolint:errcheck
	okay := false
	defer func() {
		if !okay {
			_ = os.RemoveAll(directory)
		}
	}()
	data, err := readInput(inputs[0], 128*1024*1024, false)
	if err != nil {
		return errors.New("pinned relay unavailable")
	}
	if len(data) == 0 {
		return errors.New("pinned relay empty")
	}
	if err = writePrivate(filepath.Join(directory, "ultra-relay"), data); err != nil {
		return err
	}
	binaryHash := sha256.Sum256(data)
	// Hash the exact private wire bytes, including escaping and Unicode.
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	requestHash := sha256.Sum256(raw)
	if err = writePrivate(filepath.Join(directory, "request.json"), raw); err != nil {
		return err
	}
	identityData, err := readInput(inputs[1], 65536, true)
	if err != nil {
		return errors.New("SSH identity unavailable")
	}
	pinsData, err := readInput(inputs[2], 1<<20, false)
	if err != nil {
		return errors.New("SSH pins unavailable")
	}
	identityHash, pinsHash := sha256.Sum256(identityData), sha256.Sum256(pinsData)
	if err = writePrivate(filepath.Join(directory, "identity"), identityData); err != nil {
		return err
	}
	if err = writePrivate(filepath.Join(directory, "known_hosts"), pinsData); err != nil {
		return err
	}
	job := map[string]any{
		"identity_sha256":    hex.EncodeToString(identityHash[:]),
		"known_hosts_sha256": hex.EncodeToString(pinsHash[:]),
		"schema_version":     1,
		"operation":          "configure-exit",
		"request_sha256":     hex.EncodeToString(requestHash[:]),
		"binary_sha256":      hex.EncodeToString(binaryHash[:]),
	}
	if err = writeJSON(filepath.Join(directory, "job.json"), job); err != nil {
		return err
	}
	if err = Export(filepath.Join(directory, "bundle")); err != nil {
		return err
	}
	if err = WriteRetentionReceipt(filepath.Join(directory, "bundle"), filepath.Join(directory, "bundle"), filepath.Join(directory, "bundle.retention.json"), map[string]string{"request_sha256": hex.EncodeToString(requestHash[:])}); err != nil {
		return err
	}
	if err = writePrivate(filepath.Join(directory, "prepared"), []byte("1\n")); err != nil {
		return err
	}
	if err = syncTree(directory); err != nil {
		return err
	}
	if err = syncDirectory(filepath.Dir(directory)); err != nil {
		return err
	}
	okay = true
	return nil
}

func writeJSON(path string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return writePrivate(path, data)
}

// Execute never redispatches an uncertain mutating attempt.
// Process output is suppressed because Ansible errors can include private inputs.
func Execute(ctx context.Context, directory, python, executable string) (Result, error) {
	if !filepath.IsAbs(directory) || !filepath.IsAbs(python) || !filepath.IsAbs(executable) {
		return Result{}, errors.New("absolute executor paths required")
	}
	releaseRecovery, fenceErr := recoveryExecutionAdmission(ctx, filepath.Dir(directory))
	if fenceErr != nil {
		return Result{}, fenceErr
	}
	defer releaseRecovery()
	fence, fenceErr := beginExecution(directory)
	if fenceErr != nil {
		return Result{}, fenceErr
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
	if fence != nil {
		command.Env = append(command.Env, "ULTRA_EXECUTION_GENERATION="+fence.Generation)
	}
	err := runContainedController(ctx, command, fence)
	if fence != nil {
		if closeErr := reconcileControllerExecution(*fence, err); closeErr != nil && err == nil {
			return Result{}, closeErr
		}
	}
	data, readErr := os.ReadFile(filepath.Join(directory, "receipt.json"))
	var receipt Receipt
	if readErr != nil || json.Unmarshal(data, &receipt) != nil {
		return Result{}, errors.New("ansible receipt unavailable")
	}
	if err != nil || receipt.State != "succeeded" {
		return Result{}, fmt.Errorf("ansible operation failed: %s", receipt.Code)
	}
	var seal struct {
		Operation string `json:"operation"`
	}
	sealData, readErr := os.ReadFile(filepath.Join(directory, "job.json"))
	if readErr != nil || json.Unmarshal(sealData, &seal) != nil {
		return Result{}, errors.New("ansible job unavailable")
	}
	if seal.Operation == "configure-exit" {
		if len(receipt.Result.CertPin) != 64 {
			return Result{}, errors.New("ansible certificate pin invalid")
		}
		if _, err = hex.DecodeString(receipt.Result.CertPin); err != nil {
			return Result{}, errors.New("ansible certificate pin invalid")
		}
	} else {
		return Result{}, errors.New("unsupported typed ansible operation")
	}
	return receipt.Result, nil
}

func writePrivate(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close() //nolint:errcheck
	return file.Sync()
}

func syncTree(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return syncDirectory(path)
		}
		return nil
	})
}

// The client opens all sources with its own credentials. The privileged worker
// receives descriptors, never opens a caller-supplied pathname as root.
func openInputs(binary string, request ExitRequest) ([]*os.File, error) {
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(binary) {
		return nil, errors.New("absolute pinned binary required")
	}
	var files []*os.File
	for _, path := range []string{binary, request.Identity, request.KnownHosts} {
		file, err := os.Open(path)
		if err != nil {
			closeInputs(files)
			return nil, errors.New("submitted input unavailable")
		}
		files = append(files, file)
	}
	return files, nil
}

func closeInputs(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

func readInput(file *os.File, limit int64, private bool) ([]byte, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > limit || info.Mode().Perm()&0022 != 0 {
		return nil, errors.New("invalid submitted input")
	}
	if private && info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("private submitted input required")
	}
	if _, err = file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("submitted input exceeds bounds")
	}
	return data, nil
}
