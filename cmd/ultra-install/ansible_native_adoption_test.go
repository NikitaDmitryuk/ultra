package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func nativeAdoptionFixture(t *testing.T) (*installplan.InstallPlan, []byte, []byte, []byte, []byte, []net.IP) {
	t.Helper()
	nodes := []installplan.AutomationNode{{Name: "static", Address: "192.0.2.2", Provider: "fixture"}}
	p := &installplan.InstallPlan{
		BridgeNative:  true,
		AdoptRuntime:  true,
		SchemaVersion: 2,
		Bridge:        installplan.BridgeConfig{Address: "192.0.2.1"},
		SSH:           installplan.SSHConfig{Identity: "/etc/ultra-recovery/identity"},
		Database:      installplan.DatabaseConfig{Enabled: true, Name: "fixture"},
		Automation:    &installplan.AutomationConfig{StaticNodes: nodes},
	}
	metadata := map[string]any{
		"database":          "fixture",
		"bridge_provider":   "fixture",
		"bridge_url":        "https://sync.example.com/healthz",
		"ssh_identity_file": p.SSH.Identity,
		"static_nodes":      nodes,
	}
	reconcile, _ := json.Marshal(metadata)
	metadata["bridge_ipv4"] = p.Bridge.Address
	deployment, _ := json.Marshal(metadata)
	specification, _ := json.Marshal(config.Spec{Role: config.RoleBridge})
	return p, deployment, reconcile, specification, []byte("0123456789abcdef0123456789abcdef\n"), []net.IP{net.ParseIP("192.0.2.1")}
}

func TestNativeAdoptionAttestsExplicitSameMachineAndIdentity(t *testing.T) {
	p, deployment, reconcile, specification, machine, addresses := nativeAdoptionFixture(t)
	digest, err := validateNativeAdoption(p, 0, deployment, reconcile, specification, machine, addresses)
	if err != nil || len(digest) != 64 {
		t.Fatalf("native attestation: %s %v", digest, err)
	}
	for _, test := range []struct {
		name      string
		change    func(*installplan.InstallPlan)
		euid      int
		spec      []byte
		machine   []byte
		addresses []net.IP
	}{
		{"not root", func(*installplan.InstallPlan) {}, 1000, specification, machine, addresses},
		{"implicit", func(p *installplan.InstallPlan) { p.BridgeNative = false }, 0, specification, machine, addresses},
		{"defaults", func(p *installplan.InstallPlan) { p.AdoptRuntime = false }, 0, specification, machine, addresses},
		{"legacy schema", func(p *installplan.InstallPlan) { p.SchemaVersion = 1 }, 0, specification, machine, addresses},
		{"foreign identity", func(p *installplan.InstallPlan) { p.SSH.Identity = "/tmp/different" }, 0, specification, machine, addresses},
		{"different database", func(p *installplan.InstallPlan) { p.Database.Name = "different" }, 0, specification, machine, addresses},
		{"different machine", func(*installplan.InstallPlan) {}, 0, specification, machine, []net.IP{net.ParseIP("192.0.2.3")}},
		{"missing machine identity", func(*installplan.InstallPlan) {}, 0, specification, []byte("bad"), addresses},
		{"exit", func(*installplan.InstallPlan) {}, 0, []byte(`{"role":"exit"}`), machine, addresses},
	} {
		t.Run(test.name, func(t *testing.T) {
			copy := *p
			test.change(&copy)
			if _, err := validateNativeAdoption(&copy, test.euid, deployment, reconcile, test.spec, test.machine, test.addresses); err == nil {
				t.Fatal("unattested native execution accepted")
			}
		})
	}
	var changed map[string]any
	if err = json.Unmarshal(reconcile, &changed); err != nil {
		t.Fatal(err)
	}
	changed["bridge_provider"] = "different"
	raw, _ := json.Marshal(changed)
	if _, err = validateNativeAdoption(p, 0, deployment, raw, specification, machine, addresses); err == nil {
		t.Fatal("conflicting metadata accepted")
	}
}

type nativeAdoptionTestInfo struct {
	os.FileInfo
	owner uint32
	mode  os.FileMode
}

func (i nativeAdoptionTestInfo) Sys() any {
	copy := *i.FileInfo.Sys().(*syscall.Stat_t)
	copy.Uid = i.owner
	return &copy
}
func (i nativeAdoptionTestInfo) Mode() os.FileMode { return i.mode }

func TestNativeAdoptionFixedReaderChecksFilesAndDescriptor(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "spec.json")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	uid := uint32(os.Geteuid())
	lstat := func(current string) (os.FileInfo, error) {
		info, err := os.Lstat(current)
		if err != nil {
			return nil, err
		}
		owner := uint32(0)
		mode := info.Mode()
		if current == root || current == path {
			owner = uid
		} else {
			mode = mode &^ 0022
		}
		return nativeAdoptionTestInfo{info, owner, mode}, nil
	}
	open := func(path string) (*os.File, error) {
		fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), path), nil
	}
	raw, err := readNativeAdoptionOwnedFile(path, &uid, lstat, open)
	if err != nil || string(raw) != "fixture" {
		t.Fatalf("trusted relay fixture: %s %v", raw, err)
	}

	foreign := uid + 1
	changedMetadata := func(current string) (os.FileInfo, error) {
		info, err := lstat(current)
		if err != nil {
			return nil, err
		}
		if current == path || current == root {
			return nativeAdoptionTestInfo{info, foreign, info.Mode()}, nil
		}
		return info, nil
	}
	_, err = readNativeAdoptionOwnedFile(path, &foreign, changedMetadata, open)
	if os.Geteuid() != 0 && err == nil {
		t.Fatal("descriptor owner mismatch accepted")
	}
	if os.Geteuid() == 0 && err != nil {
		t.Fatal("root-owned descriptor should remain trusted", err)
	}
	if err = os.Chmod(path, 0622); err != nil {
		t.Fatal(err)
	}
	if _, err = readNativeAdoptionOwnedFile(path, &uid, lstat, open); err == nil {
		t.Fatal("writable file accepted")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink("missing", path); err != nil {
		t.Fatal(err)
	}
	if _, err = readNativeAdoptionOwnedFile(path, &uid, lstat, open); err == nil {
		t.Fatal("symlink accepted")
	}
}
