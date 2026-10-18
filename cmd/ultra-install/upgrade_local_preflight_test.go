package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func localPreflightFixture(t *testing.T) (string, *installplan.InstallPlan, string, *automationRelease) {
	t.Helper()
	_, root, _ := forwardFixture(t)
	directory := filepath.Join(root, "upgrade-v0.0.1")
	if err := os.RemoveAll(filepath.Join(directory, "activate")); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(root, "operator-inputs", "manual-"+strings.Repeat("0", 39)+"1-"+strings.Repeat("a", 64))
	p, err := installplan.LoadConfig(filepath.Join(input, "install.config"))
	if err != nil {
		t.Fatal(err)
	}
	if err := installplan.ValidatePlan(p); err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(input, "release")
	manifest := &automationRelease{SourceCommit: localPreflightCommit, Version: "v0.0.1"}
	manifest.Assets = append(manifest.Assets, struct {
		Name string `json:"name"`
		SHA  string `json:"sha256"`
		Size int64  `json:"size"`
	}{
		Name: "ultra-ansible-runtime-linux-" + runtime.GOARCH + ".tar.gz", SHA: strings.Repeat("b", 64), Size: 1})
	writeForwardJSON(
		t,
		filepath.Join(directory, "execution-mode.json"),
		frozenExecution{Schema: 1, Target: p.Bridge.SSHHost + "|" + p.Bridge.Address,
			LockDirectory: root, OperatorDirectory: filepath.Join(root, "operator"), BootstrapEngine: "components-v1"},
	)
	writeForwardJSON(
		t,
		filepath.Join(directory, "runtime-use.json"),
		map[string]string{"runtime_directory": filepath.Join(root, "runtime-"+strings.Repeat("b", 64))},
	)
	writeForwardJSON(t, filepath.Join(directory, "readiness-diagnostic-123.json"), map[string]string{
		"stage": "Wait without discovery or private topology inspection", "node": "bridge", "code": "host_unreachable"})
	return directory, p, release, manifest
}

func TestLocalPreflightOnlyAcceptsCompleteAuditedReadinessState(t *testing.T) {
	directory, p, release, manifest := localPreflightFixture(t)
	if err := matchOperatorPlan(directory, p, release); err != nil {
		t.Fatalf("fixture plan: %v", err)
	}
	if err := operatorPrivate(directory, true); err != nil {
		t.Fatalf("fixture dir: %v", err)
	}
	if err := verifyLocalPreflightOperation(directory, p, release, manifest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"activate", "inspect", "lifecycle-applying-1", "enforce", "resume", "completed.json", "unknown", ".prepare-incomplete"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(directory, name)
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			defer os.Remove(path) //nolint:errcheck
			if verifyLocalPreflightOperation(directory, p, release, manifest) == nil {
				t.Fatal("extra durable stage accepted")
			}
		})
	}
	manifest.SourceCommit = strings.Repeat("a", 40)
	if verifyLocalPreflightOperation(directory, p, release, manifest) == nil {
		t.Fatal("unaudited protocol accepted")
	}
}

func TestLocalPreflightRejectsChangedPlanAndExecution(t *testing.T) {
	for _, name := range []string{"operator-plan.json", "execution-mode.json", "runtime-use.json", "readiness-diagnostic-123.json"} {
		t.Run(name, func(t *testing.T) {
			directory, p, release, manifest := localPreflightFixture(t)
			if err := os.WriteFile(filepath.Join(directory, name), []byte(`{}`), 0600); err != nil {
				t.Fatal(err)
			}
			if verifyLocalPreflightOperation(directory, p, release, manifest) == nil {
				t.Fatal("incomplete evidence accepted")
			}
		})
	}
}

func TestLocalPreflightInheritedLockRejectsDifferentOpenDescription(t *testing.T) {
	path := filepath.Join(t.TempDir(), "infrastructure.lock")
	first, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close() //nolint:errcheck
	if err = syscall.Flock(int(first.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	second, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if verifyLocalRecoveryLock(int(second.Fd()), path) == nil {
		t.Fatal("live original lock accepted")
	}
	fd, err := syscall.Dup(int(first.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyLocalRecoveryLock(fd, path); err != nil {
		t.Fatal(err)
	}
}
