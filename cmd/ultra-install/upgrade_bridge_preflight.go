package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// This adapter is deliberately separate from the historical local-controller
// proof. In this exact source, WaitUpgradeReadiness returns before acquiring the
// lifecycle lock or publishing reservation/inspection/activation stages.
const bridgePreflightCommit = "4c287fd4d4b44f019c40668ae51bd396ff0aaa20"

// This checks the audited stage protocol, not quiescence or authorization to
// archive a journal. The caller must also bind the original executable/release,
// config and remote attempt, and hold the sealed-origin admission lease.
func verifyBridgePreflightOperation(directory string, p *installplan.InstallPlan, release string, manifest *automationRelease) error {
	fail := errors.New("bridge_preflight_evidence_unverified")
	root := filepath.Dir(directory)
	if manifest == nil || manifest.SourceCommit != bridgePreflightCommit ||
		directory != filepath.Join(root, "upgrade-"+manifest.Version) ||
		operatorPrivate(directory, true) != nil || matchOperatorPlan(directory, p, release) != nil {
		return fail
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 3 {
		return fail
	}
	diagnostic := ""
	for _, entry := range entries {
		switch entry.Name() {
		case "operator-plan.json", "execution-mode.json":
		default:
			if diagnostic != "" || !regexp.MustCompile(`^readiness-diagnostic-[0-9]+\.json$`).MatchString(entry.Name()) {
				return fail
			}
			diagnostic = entry.Name()
		}
	}
	if diagnostic == "" {
		return fail
	}
	raw, err := readForwardEvidence(filepath.Join(directory, "execution-mode.json"))
	var mode frozenExecution
	if err != nil || decodeForwardChain(raw, &mode) != nil || mode.Schema != 1 || !mode.Local || mode.Native ||
		mode.NativeMachineSHA != "" || mode.Target != p.Bridge.SSHHost+"|"+p.Bridge.Address ||
		mode.LockDirectory != root || mode.OperatorDirectory != filepath.Join(root, "operator") ||
		mode.BootstrapEngine != "components-v1" {
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
		observation.Node != "bridge" || observation.Code != "task_failed" {
		return fail
	}
	return nil
}
