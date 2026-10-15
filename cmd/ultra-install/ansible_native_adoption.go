package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// This explicit initial executor uses the existing fixed lifecycle modules;
// it never claims an already-attested broker lease or reads a private key.
func attestNativeAdoption(p *installplan.InstallPlan) (string, error) {
	if p == nil || !p.BridgeNative || !p.AdoptRuntime || p.SchemaVersion != installplan.CurrentSchemaVersion || p.Automation == nil || os.Geteuid() != 0 {
		return "", errors.New("native_adoption_root_and_explicit_runtime_required")
	}
	relay, err := user.Lookup("ultra-relay")
	if err != nil {
		return "", errors.New("native_adoption_identity_unavailable")
	}
	relayUID, err := strconv.ParseUint(relay.Uid, 10, 32)
	if err != nil {
		return "", errors.New("native_adoption_identity_unavailable")
	}
	deployment, err := readNativeAdoptionFile("/etc/ultra-recovery/deployment.json", nil)
	if err != nil {
		return "", err
	}
	reconcile, err := readNativeAdoptionFile("/etc/ultra-recovery/reconcile.json", nil)
	if err != nil {
		return "", err
	}
	specification, err := readNativeAdoptionFile("/etc/ultra-relay/spec.json", uint32Pointer(uint32(relayUID)))
	if err != nil {
		return "", err
	}
	machine, err := readNativeAdoptionFile("/etc/machine-id", nil)
	if err != nil {
		return "", err
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return "", errors.New("native_adoption_machine_unavailable")
	}
	local := []net.IP{}
	for _, address := range addresses {
		if network, ok := address.(*net.IPNet); ok {
			local = append(local, network.IP)
		}
	}
	return validateNativeAdoption(p, 0, deployment, reconcile, specification, machine, local)
}

func uint32Pointer(value uint32) *uint32 { return &value }

// The caller supplies only one of the fixed paths above. Relay ownership is
// permitted exclusively for the installed relay directory/specification.
func readNativeAdoptionFile(path string, relayUID *uint32) ([]byte, error) {
	switch path {
	case "/etc/ultra-recovery/deployment.json", "/etc/ultra-recovery/reconcile.json", "/etc/machine-id":
		if relayUID != nil {
			return nil, errors.New("native_adoption_fixed_state_untrusted")
		}
	case "/etc/ultra-relay/spec.json":
	default:
		return nil, errors.New("native_adoption_fixed_state_untrusted")
	}

	return readNativeAdoptionOwnedFile(path, relayUID, os.Lstat, func(path string) (*os.File, error) {
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), path), nil
	})
}

func readNativeAdoptionOwnedFile(path string, relayUID *uint32, lstat func(string) (os.FileInfo, error), open func(string) (*os.File, error)) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, errors.New("native_adoption_fixed_state_untrusted") }
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fail()
	}
	trusted := func(current string, info os.FileInfo) bool {
		owner, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return false
		}
		allowed := owner.Uid == 0 || (relayUID != nil && owner.Uid == *relayUID && (current == path || current == filepath.Dir(path)))
		return allowed && info.Mode()&os.ModeSymlink == 0 && info.Mode().Perm()&0022 == 0
	}
	for current := path; ; current = filepath.Dir(current) {
		info, err := lstat(current)
		if err != nil || !trusted(current, info) {
			return fail()
		}
		if current == path && (!info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20) {
			return fail()
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	file, err := open(path)
	if err != nil {
		return fail()
	}
	defer file.Close() //nolint:errcheck
	info, err := file.Stat()
	if err != nil || !trusted(path, info) || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 1<<20 {
		return fail()
	}
	raw, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil || len(raw) > 1<<20 {
		return fail()
	}
	return raw, nil
}

// Pure validation keeps machine/location proof separate from metadata parsing.
func validateNativeAdoption(p *installplan.InstallPlan, euid int, deploymentRaw, reconcileRaw, specRaw, machine []byte, addresses []net.IP) (string, error) {
	fail := func() (string, error) { return "", errors.New("native_adoption_machine_or_policy_conflict") }
	if p == nil || !p.BridgeNative || !p.AdoptRuntime || p.SchemaVersion != installplan.CurrentSchemaVersion || p.Automation == nil || euid != 0 || !p.Database.Enabled {
		return fail()
	}
	if !validAdoptionMetadata("deployment.json", deploymentRaw) || !validAdoptionMetadata("reconcile.json", reconcileRaw) {
		return fail()
	}
	var deployment struct {
		BridgeIPv4 string                       `json:"bridge_ipv4"`
		Database   string                       `json:"database"`
		Provider   string                       `json:"bridge_provider"`
		URL        string                       `json:"bridge_url"`
		Identity   string                       `json:"ssh_identity_file"`
		Nodes      []installplan.AutomationNode `json:"static_nodes"`
	}
	var reconcile struct {
		Database string                       `json:"database"`
		Provider string                       `json:"bridge_provider"`
		URL      string                       `json:"bridge_url"`
		Identity string                       `json:"ssh_identity_file"`
		Nodes    []installplan.AutomationNode `json:"static_nodes"`
	}
	var specification config.Spec
	if json.Unmarshal(deploymentRaw, &deployment) != nil || json.Unmarshal(reconcileRaw, &reconcile) != nil || json.Unmarshal(specRaw, &specification) != nil || specification.Role != config.RoleBridge {
		return fail()
	}
	if deployment.Database == "" || deployment.Database != p.Database.Name || deployment.Database != reconcile.Database || deployment.Provider == "" || deployment.Provider != reconcile.Provider || deployment.URL == "" || deployment.URL != reconcile.URL || !reflect.DeepEqual(deployment.Nodes, reconcile.Nodes) || !reflect.DeepEqual(deployment.Nodes, p.Automation.StaticNodes) {
		return fail()
	}
	if !filepath.IsAbs(p.BridgeSSHIdentity()) || filepath.Clean(p.BridgeSSHIdentity()) != p.BridgeSSHIdentity() || p.BridgeSSHIdentity() != reconcile.Identity || (deployment.Identity != "" && deployment.Identity != reconcile.Identity) {
		return fail()
	}
	address := net.ParseIP(p.Bridge.Address)
	if address == nil || address.IsLoopback() || address.IsUnspecified() || !address.Equal(net.ParseIP(deployment.BridgeIPv4)) {
		return fail()
	}
	found := false
	for _, local := range addresses {
		if address.Equal(local) {
			found = true
		}
	}
	if !found {
		return fail()
	}
	identity := strings.TrimSpace(string(machine))
	if !regexp.MustCompile(`^[a-fA-F0-9]{32}$`).MatchString(identity) {
		return fail()
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte(identity))), nil
}
