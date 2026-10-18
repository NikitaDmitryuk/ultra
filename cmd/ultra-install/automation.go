package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"math/big"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func runAutomationCommand(action string, args []string) {
	fs := flag.NewFlagSet("ultra-install "+action, flag.ExitOnError)
	plan := fs.String("plan", "", "validated install plan; private file references only")
	configPath := fs.String("config", "", "canonical install.config path (exclusive with --plan)")
	releaseDir := fs.String("release-dir", "", "local signed release directory (overrides GitHub selection)")
	releaseSelector := fs.String("release", "latest", "GitHub release tag, or latest for the stable release")
	retryFailed := fs.Bool("retry-failed", false, "explicitly retry the same failed frozen Ansible job after recovery preflight")
	probeFile := fs.String("subscription-probe-url-file", "", "private 0600 HTTPS subscription URL file for domain acceptance")
	jobDirectory := fs.String("job-dir", "", "persistent private Ansible upgrade directory")
	python := fs.String("python", "/usr/bin/python3", "controller Python")
	ansible := fs.String("ansible-playbook", "", "pinned Ansible executable; otherwise resolve exact release runtime")
	secretsSource := fs.String("secrets-source", "canonical", "canonical or installed-runtime secret inputs (upgrade only)")
	lifecycle := fs.Bool("lifecycle", false, "explicit existing-deployment context (upgrade/status only)")
	_ = fs.Parse(args)
	if fs.NArg() > 0 {
		exitOnErr("upgrade arguments", errors.New("positional arguments are not supported"))
		return
	}
	if *lifecycle && action != "upgrade" && action != "status" {
		exitOnErr("lifecycle arguments", errors.New("lifecycle context requires upgrade or status"))
		return
	}
	if action == "upgrade" && *plan == "" && *configPath == "" {
		*configPath = "install.config"
	}
	p := readDeploymentForOperationOrExit(*plan, *configPath, action == "upgrade" || action == "status")
	if action != "upgrade" && *secretsSource != "canonical" {
		exitOnErr("secrets source", errors.New("secrets_source_upgrade_required"))
		return
	}
	exitOnErr("secrets source", selectPlanSecrets(p, *secretsSource))
	if action == "upgrade" {
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		publicKey := strings.TrimSpace(p.SourceValues["ULTRA_RELEASE_MINISIGN_PUBLIC_KEY"])
		if publicKey == "" {
			message := "trusted Minisign public key missing from canonical install.config (ULTRA_RELEASE_MINISIGN_PUBLIC_KEY)"
			if *plan != "" {
				message = "signed upgrade requires canonical --config; deployment plans do not carry the trusted Minisign key"
			}
			exitOnErr("GitHub release verification", errors.New(message))
			return
		}
		minisignPath, err := resolveMinisignExecutable()
		if err != nil {
			exitOnErr("GitHub release verification", errors.New("minisign executable required"))
			return
		}
		selectedReleaseDir := *releaseDir
		cache, err := os.UserCacheDir()
		if err != nil {
			exitOnErr("GitHub release cache", err)
			return
		}
		stagingBase := filepath.Join(cache, "ultra", "releases")
		if selectedReleaseDir == "" {
			verified, err := FetchVerifiedGitHubRelease(ctx, GitHubReleaseOptions{
				Selector:     *releaseSelector,
				PublicKey:    publicKey,
				StagingBase:  stagingBase,
				MinisignPath: minisignPath,
			})
			exitOnErr("GitHub release download", err)
			selectedReleaseDir = verified.Directory
			defer func() { exitOnErr("GitHub release close", verified.Close()) }()
		} else if *releaseSelector != "latest" {
			exitOnErr("upgrade arguments", errors.New("--release and --release-dir cannot be used together"))
			return
		} else {
			verified, err := snapshotSignedAutomationRelease(selectedReleaseDir, publicKey, stagingBase, minisignPath)
			exitOnErr("local release snapshot", err)
			selectedReleaseDir = verified.Directory
			defer func() { exitOnErr("local release snapshot close", verified.Close()) }()
		}
		_, err = verifySignedAutomationRelease(selectedReleaseDir, publicKey, minisignPath)
		exitOnErr("GitHub release verification", err)
		handoffArgs := rewriteUpgradeReleaseArgs(args, selectedReleaseDir)
		handed, err := handoffManualUpgrade(ctx, p, selectedReleaseDir, handoffArgs, minisignPath)
		if handed || err != nil {
			exitOnErr("Ansible target upgrade", err)
			return
		}
		exitOnErr(
			"Ansible upgrade",
			ansibleUpgrade(
				withUpgradeDomainProbeFile(ctx, *probeFile),
				p,
				selectedReleaseDir,
				*jobDirectory,
				*python,
				*ansible,
				*retryFailed,
			),
		)
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

// runOperatorUpgradeCommand applies the exact local release candidate prepared
// by scripts/manual-deploy.py. Its expected identities are bound by the
// operator's pinned SSH transport; normal "upgrade" remains signature-only.
func runOperatorUpgradeCommand(args []string) {
	fs := flag.NewFlagSet("ultra-install operator-upgrade", flag.ExitOnError)
	configPath := fs.String("config", "", "canonical install.config path")
	releaseDir := fs.String("release-dir", "", "operator-staged release candidate")
	sourceCommit := fs.String("source-commit", "", "expected 40-character source commit")
	version := fs.String("version", "", "expected candidate version")
	manifestSHA := fs.String("manifest-sha256", "", "expected release manifest SHA-256")
	configSHA := fs.String("config-sha256", "", "expected canonical config SHA-256")
	retryFailed := fs.Bool("retry-failed", false, "explicitly retry the same failed frozen Ansible job after recovery preflight")
	forwardOnly := fs.Bool("forward-only", false, "continue without restoring an unknown previous relay binary")
	forwardJournalFile := fs.String("forward-journal-file", "", "private archived dispatched-operation journal for forward-only recovery")
	forwardJournalSHA := fs.String("forward-journal-sha256", "", "SHA-256 of the archived forward-only journal")
	forwardPrior := fs.String("forward-prior-candidate", "", "exact failed pre-activation candidate operation directory")
	forwardPriorJournal := fs.String("forward-prior-journal-file", "", "private archived failed candidate journal")
	forwardPriorSHA := fs.String("forward-prior-journal-sha256", "", "SHA-256 of the archived failed candidate journal")
	probeFile := fs.String("subscription-probe-url-file", "", "private 0600 HTTPS subscription URL file for domain acceptance")
	jobDirectory := fs.String("job-dir", "", "persistent private Ansible upgrade directory")
	python := fs.String("python", "/usr/bin/python3", "controller Python")
	ansible := fs.String("ansible-playbook", "", "pinned Ansible executable; otherwise resolve exact release runtime")
	secretsSource := fs.String("secrets-source", "canonical", "canonical or installed-runtime secret inputs")
	_ = fs.Bool("lifecycle", false, "explicit existing-deployment context; operator upgrade is always lifecycle-only")
	_ = fs.Parse(args)
	if fs.NArg() > 0 || *configPath == "" || *releaseDir == "" || *version == "" ||
		!regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(*sourceCommit) ||
		!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(*manifestSHA) ||
		!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(*configSHA) || (*forwardOnly && *retryFailed) ||
		(*forwardOnly && (*forwardJournalFile == "" || *forwardJournalSHA == "")) ||
		(!*forwardOnly && (*forwardJournalFile != "" || *forwardJournalSHA != "")) ||
		(*forwardJournalSHA != "" && !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(*forwardJournalSHA)) {
		exitOnErr("operator upgrade arguments", errors.New("complete operator candidate identity required"))
		return
	}
	if (*forwardPrior != "" || *forwardPriorJournal != "" || *forwardPriorSHA != "") &&
		(!*forwardOnly || *forwardPrior == "" || *forwardPriorJournal == "" || !regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(*forwardPriorSHA)) {
		exitOnErr("operator upgrade prior candidate", errors.New("complete prior candidate identity required"))
		return
	}
	configRaw, err := os.ReadFile(*configPath)
	if err != nil || digestSHA256(configRaw) != *configSHA {
		exitOnErr("operator upgrade config verification", errors.New("canonical config digest mismatch"))
		return
	}
	p := readLifecycleDeploymentOrExit("", *configPath)
	exitOnErr("operator upgrade secrets", selectPlanSecrets(p, *secretsSource))
	if p.Automation == nil || p.Automation.Version != *version {
		exitOnErr("operator upgrade config verification", errors.New("candidate version does not match canonical config"))
		return
	}
	configuredRelease, err := filepath.Abs(p.Automation.ReleaseDir)
	if err != nil {
		exitOnErr("operator upgrade config verification", err)
		return
	}
	selectedRelease, err := filepath.Abs(*releaseDir)
	if err != nil || configuredRelease != selectedRelease {
		exitOnErr("operator upgrade config verification", errors.New("candidate directory does not match canonical config"))
		return
	}
	current := "/proc/self/exe"
	if _, err := verifyOperatorUpgradeRelease(selectedRelease, *sourceCommit, *version, *manifestSHA, current); err != nil {
		exitOnErr("operator upgrade release verification", err)
		return
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if *forwardJournalFile != "" {
		if !filepath.IsAbs(*forwardJournalFile) {
			exitOnErr("operator upgrade forward journal", errors.New("forward journal must be an absolute private file"))
			return
		}
		raw, readErr := readForwardEvidence(*forwardJournalFile)
		if readErr != nil || digestSHA256(raw) != *forwardJournalSHA {
			exitOnErr("operator upgrade forward journal", errors.New("forward journal verification failed"))
			return
		}
		ctx = withForwardUpgradeJournal(ctx, *forwardJournalFile, *forwardJournalSHA)
		if *forwardPrior != "" {
			ctx = context.WithValue(
				ctx,
				forwardPriorCandidateKey{},
				forwardPriorCandidate{*forwardPrior, *forwardPriorJournal, *forwardPriorSHA},
			)
		}
	}
	exitOnErr(
		"Ansible operator upgrade",
		ansibleUpgrade(
			withUpgradeDomainProbeFile(ctx, *probeFile),
			p,
			selectedRelease,
			*jobDirectory,
			*python,
			*ansible,
			*retryFailed,
			*forwardOnly,
		),
	)
}

func verifyOperatorUpgradeRelease(releaseDir, sourceCommit, version, manifestSHA, executable string) (*automationRelease, error) {
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

// rewriteUpgradeReleaseArgs pins a child installer handoff to the already
// verified immutable directory. It must not resolve "latest" a second time.
func rewriteUpgradeReleaseArgs(args []string, releaseDir string) []string {
	filtered := make([]string, 0, len(args)+2)
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			// The release pin must remain a parsed flag in the handed-off CLI.
			continue
		}
		if arg == "--release" || arg == "-release" || arg == "--release-dir" || arg == "-release-dir" {
			i++
			continue
		}
		if strings.HasPrefix(arg, "--release=") || strings.HasPrefix(arg, "-release=") || strings.HasPrefix(arg, "--release-dir=") ||
			strings.HasPrefix(arg, "-release-dir=") {
			continue
		}
		filtered = append(filtered, arg)
	}
	return append(filtered, "--release-dir", releaseDir)
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
func handoffManualUpgrade(
	ctx context.Context,
	p *installplan.InstallPlan,
	releaseDir string,
	args []string,
	minisignPath string,
) (bool, error) {
	if err := validateMinisignExecutable(minisignPath); err != nil {
		return false, errors.New("minisign executable required for installer handoff")
	}
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
	target, cleanup, err := stageManualUpgradeInstaller(releaseDir, asset.Name, asset.SHA, asset.Size)
	if err != nil {
		return false, err
	}
	defer cleanup()
	command := exec.CommandContext(ctx, target, append([]string{"upgrade"}, args...)...)
	home, _ := os.UserHomeDir()
	command.Env = manualUpgradeEnvironment(home, minisignPath)
	if command.Run() != nil {
		return true, errors.New("target_installer_upgrade_failed")
	}
	return true, nil
}

// Stage an executable copy beside the immutable signed release bundle. The
// cache remains byte-for-byte and mode-for-mode verifiable for later retention.
func stageManualUpgradeInstaller(releaseDir, name, expectedSHA string, expectedSize int64) (string, func(), error) {
	sourcePath := filepath.Join(releaseDir, name)
	info, err := os.Lstat(sourcePath)
	if err != nil || !info.Mode().IsRegular() || info.Size() != expectedSize || expectedSize <= 0 {
		return "", nil, errors.New("target_installer_asset_invalid")
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return "", nil, errors.New("target_installer_asset_unavailable")
	}
	opened, statErr := source.Stat()
	if statErr != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		_ = source.Close()
		return "", nil, errors.New("target_installer_asset_changed")
	}

	directory, err := os.MkdirTemp(filepath.Dir(releaseDir), ".ultra-installer-handoff-")
	if err != nil {
		_ = source.Close()
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	fail := func(cause error) (string, func(), error) {
		_ = source.Close()
		cleanup()
		return "", nil, cause
	}
	if err := os.Chmod(directory, 0700); err != nil {
		return fail(err)
	}
	target := filepath.Join(directory, "ultra-install")
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fail(err)
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, hash), io.LimitReader(source, expectedSize+1))
	closeSourceErr := source.Close()
	if copyErr != nil || closeSourceErr != nil || written != expectedSize || hex.EncodeToString(hash.Sum(nil)) != expectedSHA {
		_ = output.Close()
		return fail(errors.New("target_installer_copy_verification_failed"))
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		cleanup()
		return "", nil, err
	}
	if err := output.Chmod(0700); err != nil {
		_ = output.Close()
		cleanup()
		return "", nil, err
	}
	if err := output.Sync(); err != nil {
		_ = output.Close()
		cleanup()
		return "", nil, err
	}
	if err := output.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return target, cleanup, nil
}

func manualUpgradeEnvironment(home, minisignPath string) []string {
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	if home != "" {
		env = append(env, "HOME="+home)
	}
	if filepath.IsAbs(minisignPath) {
		env = append(env, upgradeMinisignPathEnv+"="+minisignPath)
	}
	return env
}
