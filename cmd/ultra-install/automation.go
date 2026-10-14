package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func runAutomationCommand(action string, args []string) {
	fs := flag.NewFlagSet("ultra-install "+action, flag.ExitOnError)
	plan := fs.String("plan", "", "validated install plan; private file references only")
	configPath := fs.String("config", "", "canonical install.config path (exclusive with --plan)")
	releaseDir := fs.String("release-dir", "", "verified immutable release directory (adopted schema v1 installations)")
	retryFailed := fs.Bool("retry-failed", false, "explicitly retry the same failed frozen Ansible job after recovery preflight")
	jobDirectory := fs.String("job-dir", "", "persistent private Ansible upgrade directory")
	python := fs.String("python", "/usr/bin/python3", "controller Python")
	ansible := fs.String("ansible-playbook", "", "pinned Ansible executable; otherwise resolve exact release runtime")
	_ = fs.Parse(args)
	p := readDeploymentOrExit(*plan, *configPath)
	if action == "upgrade" {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		handed, err := handoffManualUpgrade(ctx, p, *releaseDir, args)
		if handed || err != nil {
			exitOnErr("Ansible target upgrade", err)
			return
		}
		exitOnErr("Ansible upgrade", ansibleUpgrade(ctx, p, *releaseDir, *jobDirectory, *python, *ansible, *retryFailed))
		return
	}
	if action == "status" {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		exitOnErr("Ansible status", ansibleAutomationStatus(ctx, p, *python, *ansible))
		return
	}
	applyPlanN(p, "human")
}

type automationRelease struct {
	SchemaVersion     int      `json:"schema_version"`
	SourceCommit      string   `json:"source_commit"`
	DatabaseSchemaMin int      `json:"database_schema_min"`
	DatabaseSchemaMax int      `json:"database_schema_max"`
	Version           string   `json:"version"`
	Capabilities      []string `json:"capabilities"`
	Assets            []struct {
		Name string `json:"name"`
		SHA  string `json:"sha256"`
		Size int64  `json:"size"`
	} `json:"assets"`
}

func preflightAutomation(p *installplan.InstallPlan) error {
	if !p.FullAutomation() {
		return nil
	}
	if err := installplan.ValidatePlan(p); err != nil {
		return err
	}
	_, err := verifyAutomationRelease(p.Automation.ReleaseDir, p.Automation.Version)
	return err
}

// verifyAutomationRelease verifies every manifest asset and returns its immutable version.
func verifyAutomationRelease(releaseDir, expectedVersion string) (*automationRelease, error) {
	raw, err := os.ReadFile(filepath.Join(releaseDir, "release-manifest.json"))
	if err != nil {
		return nil, errors.New("complete release manifest unavailable")
	}
	var manifest automationRelease
	if json.Unmarshal(raw, &manifest) != nil || !validAutomationVersion(manifest.Version) || (expectedVersion != "" && manifest.Version != expectedVersion) {
		return nil, errors.New("release version mismatch")
	}
	capable := false
	for _, capability := range manifest.Capabilities {
		capable = capable || capability == "service-access-v1"
	}
	if !capable {
		return nil, errors.New("release lacks service-access-v1 capability")
	}
	seen := map[string]bool{}
	for _, asset := range manifest.Assets {
		if filepath.Base(asset.Name) != asset.Name || asset.Name == "." || seen[asset.Name] || asset.Size <= 0 || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(asset.SHA) {
			return nil, errors.New("invalid or repeated release asset")
		}
		seen[asset.Name] = true
		info, err := os.Lstat(filepath.Join(releaseDir, asset.Name))
		if err != nil || !info.Mode().IsRegular() {
			return nil, errors.New("release asset is not a regular immutable file")
		}
		file, err := os.Open(filepath.Join(releaseDir, asset.Name))
		if err != nil {
			return nil, errors.New("release asset missing")
		}
		hash := sha256.New()
		size, copyErr := io.Copy(hash, file)
		_ = file.Close()
		if copyErr != nil || size != asset.Size || hex.EncodeToString(hash.Sum(nil)) != asset.SHA {
			return nil, errors.New("release checksum mismatch")
		}
	}
	required := []string{"ultra-relay-linux-amd64", "ultra-relay-linux-arm64", "ultra-bot-linux-amd64", "ultra-bot-linux-arm64", "ultra-client-linux-amd64", "ultra-client-linux-arm64", "ultra-recovery.tar.gz"}
	if hasAutomationCapability(&manifest, "ansible-deploy-v1") {
		if manifest.SchemaVersion != 1 || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(manifest.SourceCommit) || manifest.DatabaseSchemaMin <= 0 || manifest.DatabaseSchemaMax < manifest.DatabaseSchemaMin || !hasAutomationCapability(&manifest, "provider-pool-quota-v1") || !hasAutomationCapability(&manifest, "lifecycle-gate-v1") {
			return nil, errors.New("invalid Ansible release contract")
		}
		required = append(required, "ultra-install-linux-amd64", "ultra-install-linux-arm64", "ultra-ansible.tar.gz", "ultra-ansible-runtime-linux-amd64.tar.gz", "ultra-ansible-runtime-linux-arm64.tar.gz", "mobile-bootstrap.sh", "checksums.txt")
	}
	for _, name := range required {
		if !seen[name] {
			return nil, errors.New("incomplete automation release")
		}
	}
	return &manifest, nil
}

func validAutomationVersion(version string) bool {
	return version != "latest" && regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$`).MatchString(version)
}

// Familiar operator commands enter the new release through its exact installer,
// so a retained old CLI never applies its old embedded infrastructure roles.
func handoffManualUpgrade(ctx context.Context, p *installplan.InstallPlan, releaseDir string, args []string) (bool, error) {
	if releaseDir == "" && p.Automation != nil {
		releaseDir = p.Automation.ReleaseDir
	}
	manifest, err := verifyAutomationRelease(releaseDir, "")
	if err != nil {
		return false, err
	}
	asset, err := upgradeAsset(manifest, "ultra-install-linux-"+runtime.GOARCH)
	if err != nil {
		return false, err
	}
	current, err := os.Executable()
	if err != nil {
		return false, err
	}
	if runtime.GOOS == "linux" {
		current = "/proc/self/exe"
	}
	currentSHA, err := sourceSHA(current)
	if err != nil {
		return false, err
	}
	if currentSHA == asset.SHA {
		return false, nil
	}
	target, err := filepath.Abs(filepath.Join(releaseDir, asset.Name))
	if err != nil {
		return false, err
	}
	if err = os.Chmod(target, 0700); err != nil {
		return false, err
	}
	command := exec.CommandContext(ctx, target, append([]string{"upgrade"}, args...)...)
	command.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	if home, err := os.UserHomeDir(); err == nil {
		command.Env = append(command.Env, "HOME="+home)
	}
	if command.Run() != nil {
		return true, errors.New("target_installer_upgrade_failed")
	}
	return true, nil
}
