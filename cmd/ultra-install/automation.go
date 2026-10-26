package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"time"

	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// An omitted flag preserves historical frozen requests; a supplied value applies
// only to activation and must match any existing immutable activation request.
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

func runAutomationCommand(action string, args []string) {
	fs := flag.NewFlagSet("ultra-install "+action, flag.ExitOnError)
	plan := fs.String("plan", "", "validated install plan; private file references only")
	configPath := fs.String("config", "", "canonical install.config path (exclusive with --plan)")
	releaseDir := fs.String("release-dir", "", "local signed release directory for optional automation status")
	format := fs.String("format", "human", "human or json")
	operatorStateDir := fs.String("operator-state-dir", "", "explicit local execution state root for an unprivileged operator")
	python := fs.String("python", "/usr/bin/python3", "controller Python")
	ansible := fs.String("ansible-playbook", "", "pinned Ansible executable for optional automation status")
	lifecycle := fs.Bool("lifecycle", false, "explicit existing-deployment context (status only)")
	preservePrimary := fs.Bool(
		"preserve-primary",
		false,
		"bootstrap application components while preserving the existing PostgreSQL primary",
	)
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		exitOnErr("automation arguments", errors.New("positional arguments are not supported"))
		return
	}
	if action != "bootstrap" && action != "status" {
		exitOnErr("automation action", errors.New("legacy_upgrade_command_removed"))
		return
	}
	if *lifecycle && action != "status" {
		exitOnErr("lifecycle arguments", errors.New("lifecycle context requires status"))
		return
	}
	if *preservePrimary && action != "bootstrap" {
		exitOnErr("preserved primary arguments", errors.New("bootstrap_preserved_primary_arguments_invalid"))
		return
	}
	p := readDeploymentForOperationOrExit(*plan, *configPath, action == "status")
	if *preservePrimary {
		if err := authorizePreservedPrimaryBootstrap(p); err != nil {
			exitOnErr("preserved primary authorization", err)
			return
		}
	}
	exitOnErr("secrets source", selectPlanSecrets(p, "canonical"))
	if action == "status" {
		var err error
		p, err = statusPlanWithRelease(p, *releaseDir)
		exitOnErr("status release", err)
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		report := installplan.Doctor(ctx, p, installplan.NetworkDoctorOptions(3*time.Second))
		if p.Automation != nil {
			if err := ansibleAutomationStatus(ctx, p, *python, *ansible, *format != "json"); err != nil {
				report.Issues = append(
					report.Issues,
					installplan.Issue{
						Severity: installplan.SeverityWarning,
						Code:     "automation_status_unavailable",
						Message:  "auxiliary automation status is unavailable",
					},
				)
			}
		}
		if *format == "json" {
			writeJSON(os.Stdout, report)
		} else {
			if report.OK {
				fmt.Println("status: core inputs and network checks passed")
			}
			for _, issue := range report.Issues {
				fmt.Printf("%s [%s] %s\n", issue.Severity, issue.Code, issue.Message)
			}
		}
		if !report.OK {
			os.Exit(1)
		}
		return
	}
	if action == "bootstrap" {
		if err := configureOperatorExecutionState(*operatorStateDir); err != nil {
			exitOnErr("operator identity", err)
			return
		}
	}
	applyPlanN(p, "human")
}

func verifyProductionCandidateRelease(releaseDir, sourceCommit, version, manifestSHA, executable string) (*automationRelease, error) {
	if !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(sourceCommit) || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(manifestSHA) {
		return nil, errors.New("invalid operator candidate identity")
	}
	commitNumber, ok := new(big.Int).SetString(sourceCommit, 16)
	if !ok || version != "v0.0."+commitNumber.String() {
		return nil, errors.New("operator candidate version does not match source commit")
	}
	info, err := os.Lstat(releaseDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("candidate directory must be a real directory")
	}
	manifestInfo, err := os.Lstat(filepath.Join(releaseDir, "release-manifest.json"))
	if err != nil || !manifestInfo.Mode().IsRegular() {
		return nil, errors.New("candidate manifest must be a regular file")
	}
	manifestRaw, err := os.ReadFile(filepath.Join(releaseDir, "release-manifest.json"))
	if err != nil || digestSHA256(manifestRaw) != manifestSHA {
		return nil, errors.New("candidate manifest digest mismatch")
	}
	manifest, err := verifyAutomationRelease(releaseDir, version)
	if err != nil || manifest.SourceCommit != sourceCommit || len(manifest.Assets) != 14 {
		return nil, errors.New("candidate manifest identity or assets invalid")
	}
	allowed := map[string]bool{"release-manifest.json": true, "candidate.json": true}
	for _, asset := range manifest.Assets {
		allowed[asset.Name] = true
	}
	entries, err := os.ReadDir(releaseDir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] || entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return nil, errors.New("candidate directory contains an unexpected or non-regular file")
		}
	}
	asset, err := upgradeAsset(manifest, "ultra-install-linux-"+runtime.GOARCH)
	if err != nil {
		return nil, err
	}
	executableSHA, err := sourceSHA(executable)
	if err != nil || executableSHA != asset.SHA {
		return nil, errors.New("running installer is not the verified release asset")
	}
	return manifest, nil
}

func digestSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
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
	if json.Unmarshal(raw, &manifest) != nil || !validAutomationVersion(manifest.Version) ||
		(expectedVersion != "" && manifest.Version != expectedVersion) {
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
		if filepath.Base(asset.Name) != asset.Name || asset.Name == "." || seen[asset.Name] || asset.Size <= 0 ||
			!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(asset.SHA) {
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
	required := []string{
		"ultra-relay-linux-amd64",
		"ultra-relay-linux-arm64",
		"ultra-bot-linux-amd64",
		"ultra-bot-linux-arm64",
		"ultra-client-linux-amd64",
		"ultra-client-linux-arm64",
		"ultra-recovery.tar.gz",
	}
	if hasAutomationCapability(&manifest, "ansible-deploy-v1") {
		if manifest.SchemaVersion != 1 || !regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(manifest.SourceCommit) ||
			manifest.DatabaseSchemaMin <= 0 ||
			manifest.DatabaseSchemaMax < manifest.DatabaseSchemaMin ||
			!hasAutomationCapability(&manifest, "provider-pool-quota-v1") ||
			!hasAutomationCapability(&manifest, "lifecycle-gate-v1") {
			return nil, errors.New("invalid Ansible release contract")
		}
		required = append(
			required,
			"ultra-install-linux-amd64",
			"ultra-install-linux-arm64",
			"ultra-ansible.tar.gz",
			"ultra-ansible-runtime-linux-amd64.tar.gz",
			"ultra-ansible-runtime-linux-arm64.tar.gz",
			"mobile-bootstrap.sh",
			"checksums.txt",
		)
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
