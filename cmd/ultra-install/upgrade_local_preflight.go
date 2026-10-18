package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"syscall"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// This source revision was audited for durable stage publication before every
// command.Run and for readiness occurring before lifecycle/discovery/activation.
// This is intentionally not a protocol for arbitrary legacy releases.
const localPreflightCommit = "00ec0b85988a641e73779db7a6f63a3ab8eb980f"

func verifyLocalPreflightOperation(directory string, p *installplan.InstallPlan, release string, manifest *automationRelease) error {
	fail := errors.New("local_preflight_evidence_unverified")
	root := filepath.Dir(directory)
	if manifest.SourceCommit != localPreflightCommit || directory != filepath.Join(root, "upgrade-"+manifest.Version) ||
		matchOperatorPlan(directory, p, release) != nil || operatorPrivate(directory, true) != nil {
		return fmt.Errorf("%w: identity", fail)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 4 {
		return fmt.Errorf("%w: inventory", fail)
	}
	diagnostic := ""
	for _, entry := range entries {
		switch entry.Name() {
		case "operator-plan.json", "execution-mode.json", "runtime-use.json":
		default:
			if !regexp.MustCompile(`^readiness-diagnostic-[0-9]+\.json$`).MatchString(entry.Name()) || diagnostic != "" {
				return fail
			}
			diagnostic = entry.Name()
		}
	}
	if diagnostic == "" {
		return fmt.Errorf("%w: execution", fail)
	}
	planRaw, err := readForwardEvidence(filepath.Join(directory, "operator-plan.json"))
	var identity map[string]string
	if err != nil || decodeForwardChain(planRaw, &identity) != nil || len(identity) != 1 || identity["plan_sha256"] == "" {
		return fmt.Errorf("%w: observation", fail)
	}
	raw, err := readForwardEvidence(filepath.Join(directory, "execution-mode.json"))
	var mode frozenExecution
	if err != nil || decodeForwardChain(raw, &mode) != nil || mode.Schema != 1 || mode.Local || mode.Native ||
		mode.Target != p.Bridge.SSHHost+"|"+p.Bridge.Address || mode.LockDirectory != root ||
		mode.OperatorDirectory != filepath.Join(root, "operator") || mode.BootstrapEngine != "components-v1" {
		return fail
	}
	raw, err = readForwardEvidence(filepath.Join(directory, diagnostic))
	var observation struct {
		Stage string `json:"stage"`
		Node  string `json:"node"`
		Code  string `json:"code"`
	}
	if err != nil || decodeForwardChain(raw, &observation) != nil ||
		observation.Stage != "Wait without discovery or private topology inspection" ||
		observation.Node != "bridge" ||
		observation.Code != "host_unreachable" ||
		verifyForwardRuntimeUse(filepath.Join(directory, "runtime-use.json"), root, manifest) != nil {
		return fail
	}
	return nil
}

// Check the inherited descriptions, then close the helper's duplicates. The
// wrapper owns the original OFDs through archive publication and directory
// fsync. A helper failure before acknowledgment aborts wrapper publication.
func verifyLocalRecoveryLock(fd int, path string) error {
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		return errors.New("local_preflight_lock_invalid")
	}
	defer f.Close() //nolint:errcheck
	actual, err := f.Stat()
	expected, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(actual, expected) || operatorPrivate(path, false) != nil {
		return errors.New("local_preflight_lock_invalid")
	}
	return syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
}

func runLocalPreflightProof(args []string) {
	fs := flag.NewFlagSet("local-preflight-proof", flag.ExitOnError)
	config := fs.String("config", "", "exact historical canonical config")
	release := fs.String("release-dir", "", "retained local candidate")
	directory := fs.String("job-dir", "", "retained pre-readiness operation")
	manifestSHA := fs.String("manifest-sha256", "", "pinned manifest")
	configSHA := fs.String("config-sha256", "", "pinned config")
	nonce := fs.String("nonce", "", "wrapper challenge")
	operatorFD := fs.Int("operator-lock-fd", -1, "inherited original operator lock")
	infraFD := fs.Int("infrastructure-lock-fd", -1, "inherited original infrastructure lock")
	_ = fs.Parse(args)
	fail := func(err error) { exitOnErr("local preflight proof", err) }
	if fs.NArg() != 0 || !runtimeHostValidDigest(*nonce) {
		fail(errors.New("local_preflight_arguments_invalid"))
		return
	}
	root := filepath.Dir(*directory)
	fail(verifyLocalRecoveryLock(*operatorFD, filepath.Join(root, "operator", "infrastructure.lock")))
	fail(verifyLocalRecoveryLock(*infraFD, filepath.Join(root, "infrastructure.lock")))
	raw, err := os.ReadFile(*config)
	if err != nil || digestSHA256(raw) != *configSHA {
		fail(errors.New("local_preflight_config_changed"))
		return
	}
	p, err := installplan.LoadConfig(*config)
	fail(err)
	fail(installplan.ValidatePlan(p))
	if p.Automation == nil || p.Automation.ReleaseDir != *release {
		fail(errors.New("local_preflight_release_changed"))
		return
	}
	manifest, err := verifyOperatorUpgradeRelease(*release, localPreflightCommit, p.Automation.Version, *manifestSHA,
		filepath.Join(*release, "ultra-install-linux-"+runtime.GOARCH))
	fail(err)
	fail(verifyLocalPreflightOperation(*directory, p, *release, manifest))
	proof := map[string]any{
		"schema":          1,
		"nonce":           *nonce,
		"config_sha256":   *configSHA,
		"manifest_sha256": *manifestSHA,
		"pre_mutation":    true,
	}
	_ = json.NewEncoder(os.Stdout).Encode(proof)
	// EOF, timeout, or a wrapper that never completes its own checks is failure.
	ack := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			ack <- scanner.Text()
		} else {
			ack <- ""
		}
	}()
	select {
	case value := <-ack:
		if value != "ack "+*nonce {
			fail(errors.New("local_preflight_ack_required"))
			return
		}
	case <-time.After(90 * time.Second):
		fail(errors.New("local_preflight_ack_timeout"))
		return
	}
	raw, err = os.ReadFile(*config)
	if err != nil || digestSHA256(raw) != *configSHA {
		fail(errors.New("local_preflight_config_changed"))
		return
	}
	fail(verifyLocalPreflightOperation(*directory, p, *release, manifest))
	fmt.Println("acknowledged " + *nonce)
}
