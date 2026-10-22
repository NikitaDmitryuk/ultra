package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// O remains the fleet authority, A owns the attached OFD, and B is fresh. Keep
// the exact O->A ledger before the broker replaces its latest handoff with A->B.
type forwardChainIntent struct {
	Schema                 int    `json:"schema"`
	ProofSHA               string `json:"proof_sha256"`
	PriorJournalSHA        string `json:"prior_journal_sha256"`
	OriginalID             string `json:"original_id"`
	PriorID                string `json:"prior_id"`
	NewID                  string `json:"new_id"`
	PriorEvidenceSHA       string `json:"prior_evidence_sha256"`
	OriginalHandoffSHA     string `json:"original_handoff_sha256"`
	OriginalEvidenceSHA    string `json:"original_evidence_sha256"`
	OriginalRetirementJSON string `json:"original_retirement_json"`
	OriginalRetirementSHA  string `json:"original_retirement_sha256"`
}

type forwardChainLedger struct {
	Version int      `json:"version"`
	IDs     []string `json:"ids"`
	Handoff *struct {
		OldID string `json:"old_id"`
		NewID string `json:"new_id"`
	} `json:"handoff"`
}

func decodeForwardChain(raw []byte, value any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("upgrade_forward_chain_evidence_invalid")
	}
	return nil
}
func sameForwardJSON(a, b any) bool {
	x, e := json.Marshal(a)
	y, f := json.Marshal(b)
	if e != nil || f != nil {
		return false
	}
	var left, right any
	return json.Unmarshal(x, &left) == nil && json.Unmarshal(y, &right) == nil && reflect.DeepEqual(left, right)
}
func checkForwardChainLedger(raw []byte, oldID, newID string) (forwardChainLedger, error) {
	var l forwardChainLedger
	fail := errors.New("upgrade_forward_chain_retirement_unverified")
	if decodeForwardChain(raw, &l) != nil || l.Version != 1 || l.IDs == nil || l.Handoff == nil || l.Handoff.OldID != oldID ||
		l.Handoff.NewID != newID ||
		oldID == newID {
		return l, fail
	}
	seen := map[string]bool{}
	for _, id := range l.IDs {
		if !regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`).MatchString(id) || seen[id] {
			return l, fail
		}
		seen[id] = true
	}
	if !seen[oldID] || seen[newID] {
		return l, fail
	}
	return l, nil
}
func forwardSavedRequest(stage string) (map[string]any, map[string]any, error) {
	raw, err := readForwardEvidence(filepath.Join(stage, "request.json"))
	var r struct {
		Inventory map[string]any `json:"inventory"`
		Variables map[string]any `json:"variables"`
	}
	if err != nil || json.Unmarshal(raw, &r) != nil || r.Inventory == nil || r.Variables == nil {
		return nil, nil, errors.New("upgrade_forward_chain_request_invalid")
	}
	if _, err = expectedFrozenLocalRequest(raw, r.Inventory, r.Variables); err != nil {
		return nil, nil, errors.New("upgrade_forward_chain_request_invalid")
	}
	return r.Inventory, r.Variables, nil
}

// Validate the exact exported source against A's release archive, then check
// request identity and terminal receipt/result evidence. Names convey no trust.
func verifyForwardSavedStage(
	stage, archive, operation string,
	inventory, variables, result map[string]any,
	diagnostic *deployansible.Diagnostic,
) (map[string]any, error) {
	fail := errors.New("upgrade_forward_chain_stage_unverified")
	if operatorPrivate(stage, true) != nil || verifyForwardDrainFiles(stage, archive) != nil {
		return nil, fail
	}
	inv, vars, err := forwardSavedRequest(stage)
	if err != nil || (inventory != nil && !sameForwardJSON(inv, inventory)) || (variables != nil && !sameForwardJSON(vars, variables)) {
		return nil, fail
	}
	raw, err := readForwardEvidence(filepath.Join(stage, "request.json"))
	if err != nil {
		return nil, fail
	}
	digest := digestSHA256(raw)
	type record struct {
		Schema     int                       `json:"schema_version"`
		Operation  string                    `json:"operation"`
		Request    string                    `json:"request_sha256"`
		Binary     string                    `json:"binary_sha256"`
		State      string                    `json:"state,omitempty"`
		Code       string                    `json:"code,omitempty"`
		ExitCode   *int                      `json:"exit_code,omitempty"`
		Diagnostic *deployansible.Diagnostic `json:"diagnostic,omitempty"`
		StartedAt  *int64                    `json:"started_at,omitempty"`
		FinishedAt *int64                    `json:"finished_at,omitempty"`
		Result     map[string]any            `json:"result,omitempty"`
	}
	var receipt record
	for _, name := range []string{"job.json", "receipt.json"} {
		raw, err := readForwardEvidence(filepath.Join(stage, name))
		var r record
		if err != nil || decodeForwardChain(raw, &r) != nil || r.Schema != 1 || r.Operation != operation || r.Request != digest ||
			r.Binary != digest {
			return nil, fail
		}
		if name == "job.json" {
			if r.State != "" || r.Code != "" || r.ExitCode != nil || r.Diagnostic != nil || r.StartedAt != nil || r.FinishedAt != nil ||
				r.Result != nil {
				return nil, fail
			}
		} else {
			receipt = r
		}
	}
	if receipt.StartedAt == nil || receipt.FinishedAt == nil || *receipt.StartedAt <= 0 || *receipt.FinishedAt < *receipt.StartedAt {
		return nil, fail
	}
	if diagnostic != nil {
		if receipt.State != "failed" || receipt.Code != "ansible_failed" || receipt.ExitCode == nil || *receipt.ExitCode != 2 ||
			receipt.Diagnostic == nil ||
			*receipt.Diagnostic != *diagnostic ||
			receipt.Result != nil {
			return nil, fail
		}
		raw, err := readForwardEvidence(filepath.Join(stage, "diagnostic.json"))
		var saved deployansible.Diagnostic
		if err != nil || decodeForwardChain(raw, &saved) != nil || saved != *diagnostic {
			return nil, fail
		}
		if _, err := os.Lstat(filepath.Join(stage, "result.json")); !os.IsNotExist(err) {
			return nil, fail
		}
	} else {
		if receipt.State != "succeeded" || receipt.Code != "" || receipt.ExitCode != nil || receipt.Diagnostic != nil || receipt.Result == nil {
			return nil, fail
		}
		raw, err := readForwardEvidence(filepath.Join(stage, "result.json"))
		var saved map[string]any
		if err != nil || json.Unmarshal(raw, &saved) != nil || !sameForwardJSON(saved, receipt.Result) || (result != nil && !sameForwardJSON(result, saved)) {
			return nil, fail
		}
	}
	return receipt.Result, nil
}

func forwardChainHosts(inv map[string]any) (map[string]string, bool) {
	all, ok := inv["all"].(map[string]any)
	if !ok {
		return nil, false
	}
	children, ok := all["children"].(map[string]any)
	if !ok {
		return nil, false
	}
	found := map[string]string{}
	for name, raw := range children {
		group, ok := raw.(map[string]any)
		if !ok {
			return nil, false
		}
		nodes, ok := group["hosts"].(map[string]any)
		if !ok {
			return nil, false
		}
		for alias, raw := range nodes {
			host, ok := raw.(map[string]any)
			if !ok {
				return nil, false
			}
			if name == "databases" && alias == "bridge" && len(host) == 0 {
				continue
			}
			if name != "bridge" && name != "exits" {
				return nil, false
			}
			address, ok := host["ansible_host"].(string)
			if !ok || address == "" {
				return nil, false
			}
			key := "bridge"
			if name == "bridge" {
				if alias != "bridge" {
					return nil, false
				}
			} else {
				id, ok := host["ultra_exit_id"].(string)
				if !ok || !regexp.MustCompile(`^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$`).MatchString(id) {
					return nil, false
				}
				key = id
			}
			if _, exists := found[key]; exists {
				return nil, false
			}
			found[key] = address
		}
	}
	return found, found["bridge"] != ""
}

// Compare only observed UUID/address pairs; config desires cannot authorize a
// new host. Fresh census always uses the complete original O inventory.
func forwardChainFleet(original, candidate map[string]any, bridgeOnly bool) bool {
	a, ok := forwardChainHosts(original)
	if !ok {
		return false
	}
	b, ok := forwardChainHosts(candidate)
	if !ok {
		return false
	}
	if bridgeOnly {
		return len(b) == 1 && b["bridge"] == a["bridge"]
	}
	return reflect.DeepEqual(a, b)
}
func forwardDomainVariables(p *installplan.InstallPlan, root, directory string) map[string]any {
	ingress, dns := p.Automation.Ingress, p.Automation.DNS
	mode := "direct"
	if ingress.ForwardHost != "" {
		mode = "forward"
	}
	return map[string]any{
		"ultra_lock_directory":             root,
		"ultra_upgrade_domain_transaction": digestSHA256([]byte(lifecycleID(directory))),
		"ultra_upgrade_domain_desired": map[string]any{
			"subscription": p.PublicSubscriptionDomain(),
			"vpn":          ingress.Domain,
			"backend":      p.Bot.Domain,
			"public_host":  p.Bridge.PublicHost,
		},
		"ultra_upgrade_domain_policy": map[string]any{
			"email":             ingress.Email,
			"ingress_mode":      mode,
			"forward_host":      ingress.ForwardHost,
			"dns_ttl":           dns.TTL,
			"backend_port":      ingress.BackendPort,
			"gateway_port":      ingress.GatewayPort,
			"staging_port":      ingress.StagingPort,
			"status_port":       ingress.StatusPort,
			"experimental_port": ingress.ExperimentalPort,
			"age_recipient":     p.Automation.AgeRecipient,
			"bridge_provider":   p.Automation.BridgeProvider,
			"static_nodes":      p.Automation.StaticNodes,
			"admin_telegram_id": p.Automation.AdminTelegramID,
			"bridge_ipv4":       p.Automation.BridgeIPv4,
			"state_paths":       append([]string{}, p.Automation.StatePaths...),
			"artifact_paths":    append([]string{}, p.Automation.ArtifactPaths...),
		},
	}
}
func verifyForwardRecoveryTools(directory, archive string) (result error) {
	fail := errors.New("upgrade_forward_chain_tools_invalid")
	if operatorPrivate(directory, true) != nil {
		return fail
	}
	f, err := os.Open(archive)
	if err != nil {
		return fail
	}
	defer func() {
		if err := f.Close(); err != nil && result == nil {
			result = fail
		}
	}()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fail
	}
	defer func() {
		if err := gz.Close(); err != nil && result == nil {
			result = fail
		}
	}()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil || h.Typeflag != tar.TypeReg ||
			(!regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]+\.(py|service|timer)$`).MatchString(h.Name) && h.Name != "ssh_policy.json") ||
			seen[h.Name] ||
			h.Size < 0 ||
			h.Size > 1048576 ||
			len(seen) >= 64 {
			return fail
		}
		data, err := io.ReadAll(io.LimitReader(tr, 1048577))
		if err != nil || int64(len(data)) != h.Size {
			return fail
		}
		saved, err := readForwardEvidence(filepath.Join(directory, h.Name))
		if err != nil || !bytes.Equal(data, saved) {
			return fail
		}
		seen[h.Name] = true
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(seen) {
		return fail
	}
	for _, entry := range entries {
		if !seen[entry.Name()] {
			return fail
		}
	}
	return nil
}

func verifyForwardPostHandoffArtifacts(
	old forwardOldOperation,
	root, directory, release string,
	plan *installplan.InstallPlan,
) (map[string]bool, error) {
	fail := errors.New("upgrade_forward_chain_artifacts_unverified")
	allowed := map[string]bool{
		"inspect":               true,
		"hosts":                 true,
		"domain-inspect":        true,
		"architectures":         true,
		"recovery-bundle":       true,
		"identity":              true,
		"inventory.frozen.json": true,
	}
	archive := filepath.Join(release, "ultra-ansible.tar.gz")
	if plan.Automation == nil || plan.Automation.Ingress == nil || plan.Automation.DNS == nil ||
		plan.SourceValues["ULTRA_UPGRADE_BASELINE_FILE"] != "" {
		return nil, fail
	}
	inspectInv, _, err := forwardSavedRequest(filepath.Join(directory, "inspect"))
	if err != nil || !forwardChainFleet(old.Inventory, inspectInv, true) {
		return nil, fail
	}
	observed, err := verifyForwardSavedStage(
		filepath.Join(directory, "inspect"),
		archive,
		"inspect-upgrade",
		inspectInv,
		map[string]any{"ultra_lock_directory": root},
		nil,
		nil,
	)
	if err != nil {
		return nil, fail
	}
	raw, _ := json.Marshal(observed)
	var inspection upgradeInspection
	if json.Unmarshal(raw, &inspection) != nil || inspection.ObservedAt <= 0 || inspection.Identity == "" || len(inspection.Nodes) == 0 ||
		len(inspection.Nodes) > 16 {
		return nil, fail
	}
	identity, err := readForwardEvidence(filepath.Join(directory, "identity"))
	if err != nil || string(identity) != inspection.Identity {
		return nil, fail
	}
	originalHosts, ok := forwardChainHosts(old.Inventory)
	if !ok || len(originalHosts) != len(inspection.Nodes)+1 {
		return nil, fail
	}
	hostInv, hostVars, err := forwardSavedRequest(filepath.Join(directory, "hosts"))
	if err != nil || !forwardChainFleet(old.Inventory, hostInv, false) ||
		!sameForwardJSON(
			hostVars,
			map[string]any{"ultra_lock_directory": root, "ultra_release_inspection_directory": filepath.Join(directory, "architectures")},
		) {
		return nil, fail
	}
	if _, err := verifyForwardSavedStage(filepath.Join(directory, "hosts"), archive, "inspect-release-hosts", hostInv, hostVars, map[string]any{"verified": true}, nil); err != nil {
		return nil, fail
	}
	archs := map[string]bool{"bridge.json": true}
	for _, node := range inspection.Nodes {
		alias := "exit_" + strings.ReplaceAll(node.ID, "-", "")
		if !regexp.MustCompile(`^exit_[a-f0-9]{32}$`).MatchString(alias) || archs[alias+".json"] ||
			originalHosts[node.ID] != node.Address ||
			node.Pins == "" {
			return nil, fail
		}
		archs[alias+".json"] = true
		pins, err := readForwardEvidence(filepath.Join(directory, alias+".pins"))
		if err != nil || string(pins) != node.Pins {
			return nil, fail
		}
		allowed[alias+".pins"] = true
	}
	entries, err := os.ReadDir(filepath.Join(directory, "architectures"))
	if err != nil || len(entries) != len(archs) || operatorPrivate(filepath.Join(directory, "architectures"), true) != nil {
		return nil, fail
	}
	for _, entry := range entries {
		raw, err := readForwardEvidence(filepath.Join(directory, "architectures", entry.Name()))
		var arch struct {
			Architecture string `json:"architecture"`
		}
		if !archs[entry.Name()] || err != nil || decodeForwardChain(raw, &arch) != nil ||
			(arch.Architecture != "amd64" && arch.Architecture != "arm64") {
			return nil, fail
		}
	}
	frozen, err := readForwardEvidence(filepath.Join(directory, "inventory.frozen.json"))
	var frozenInv map[string]any
	if err != nil || json.Unmarshal(frozen, &frozenInv) != nil || !forwardChainFleet(old.Inventory, frozenInv, false) {
		return nil, fail
	}
	diagnostic := deployansible.Diagnostic{
		Stage: "Bind public evidence without exporting environment or credentials",
		Node:  "bridge",
		Code:  "task_failed",
	}
	if _, err := verifyForwardSavedStage(filepath.Join(directory, "domain-inspect"), archive, "inspect-upgrade-domains", frozenInv, forwardDomainVariables(plan, root, directory), nil, &diagnostic); err != nil {
		return nil, fail
	}
	if verifyForwardRecoveryTools(filepath.Join(directory, "recovery-bundle"), filepath.Join(release, "ultra-recovery.tar.gz")) != nil {
		return nil, fail
	}
	entries, err = os.ReadDir(directory)
	if err != nil {
		return nil, fail
	}
	maintenance := 0
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "forward-maintenance-") {
			continue
		}
		_, err := verifyForwardSavedStage(
			filepath.Join(directory, entry.Name()),
			archive,
			"contain-upgrade",
			old.Inventory,
			map[string]any{"ultra_lock_directory": root, "ultra_lifecycle_id": lifecycleID(directory)},
			map[string]any{"verified": true, "maintenance_id": lifecycleID(directory)},
			nil,
		)
		if err != nil {
			return nil, fail
		}
		allowed[entry.Name()] = true
		maintenance++
	}
	if maintenance == 0 {
		return nil, fail
	}
	return allowed, nil
}
func forwardCandidateFingerprint(directory string) (string, error) {
	hashes := map[string]string{}
	err := filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == directory {
			return nil
		}
		rel, err := filepath.Rel(directory, path)
		if err != nil {
			return err
		}
		parts := strings.Split(rel, string(filepath.Separator))
		// Each excluded tree has already passed archive/private workspace validation.
		if len(parts) == 2 && entry.IsDir() && (parts[1] == "bundle" || parts[1] == ".ansible" || parts[1] == "ansible-tmp") {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return operatorPrivate(path, true)
		}
		raw, err := readForwardEvidence(path)
		if err != nil {
			return err
		}
		hashes[filepath.ToSlash(rel)] = digestSHA256(raw)
		return nil
	})
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(hashes)
	if err != nil {
		return "", err
	}
	return digestSHA256(raw), nil
}
func forwardOriginalEvidence(proof forwardUpgradeJournal, old forwardOldOperation) (string, error) {
	hashes := map[string]string{"journal": proof.SHA256}
	for _, name := range []string{"request.json", "job.json", "receipt.json"} {
		raw, err := readForwardEvidence(filepath.Join(old.Directory, "activate", name))
		if err != nil {
			return "", err
		}
		hashes["activate/"+name] = digestSHA256(raw)
	}
	raw, err := readForwardEvidence(filepath.Join(old.Directory, "operator-plan.json"))
	if err != nil {
		return "", err
	}
	hashes["operator-plan.json"] = digestSHA256(raw)
	encoded, err := json.Marshal(hashes)
	if err != nil {
		return "", err
	}
	return digestSHA256(encoded), nil
}

func verifyForwardChainDestination(proof forwardUpgradeJournal, prior forwardOldOperation, root, directory, archive string) error {
	fail := errors.New("upgrade_forward_chain_destination_invalid")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fail
	}
	for _, entry := range entries {
		path := filepath.Join(directory, entry.Name())
		switch entry.Name() {
		case "operator-plan.json", "execution-mode.json", "runtime-use.json", "forward-chain.json":
			if _, err := readForwardEvidence(path); err != nil {
				return fail
			}
		case "forward-handoff.json":
			if verifyForwardIntent(proof, prior, root, directory) != nil {
				return fail
			}
		default:
			if !strings.HasPrefix(entry.Name(), "handoff-drain-") {
				return fail
			}
			if archive == "" || verifyForwardCensusAttempt(proof, prior, root, directory, path, archive) != nil {
				return fail
			}
		}
	}
	return nil
}

// A failed or explicitly interrupted census is authenticated history only. It
// may not authorize handoff; the caller always executes a new full census under
// the predecessor lease before saving an intent or superseding lifecycle state.
func verifyForwardCensusAttempt(
	proof forwardUpgradeJournal,
	old forwardOldOperation,
	lockDirectory, directory, stage, archive string,
) error {
	if _, err := forwardDrainIntent(proof, old, lockDirectory, directory, stage); err == nil {
		return verifyForwardDrainFiles(stage, archive)
	}
	fail := errors.New("upgrade_forward_saved_census_attempt_unverified")
	if !filepath.IsAbs(stage) || filepath.Clean(stage) != stage || filepath.Dir(stage) != directory ||
		!strings.HasPrefix(filepath.Base(stage), "handoff-drain-") || operatorPrivate(stage, true) != nil ||
		verifyForwardDrainFiles(stage, archive) != nil {
		return fail
	}
	request, readErr := readForwardEvidence(filepath.Join(stage, "request.json"))
	expected, err := expectedFrozenLocalRequest(
		request,
		old.Inventory,
		forwardDrainVariables(lockDirectory, old.ID, lifecycleID(directory)),
	)
	if err != nil || readErr != nil || !bytes.Equal(request, expected) {
		return fail
	}
	requestSHA := digestSHA256(request)
	jobRaw, err := readForwardEvidence(filepath.Join(stage, "job.json"))
	if err != nil {
		return fail
	}
	var job struct {
		Schema     int    `json:"schema_version"`
		Operation  string `json:"operation"`
		RequestSHA string `json:"request_sha256"`
		BinarySHA  string `json:"binary_sha256"`
	}
	if decodeForwardChain(jobRaw, &job) != nil || job.Schema != 1 || job.Operation != "drain-upgrade-workers" ||
		job.RequestSHA != requestSHA || job.BinarySHA != requestSHA {
		return fail
	}
	receiptPath := filepath.Join(stage, "receipt.json")
	receiptRaw, err := readForwardEvidence(receiptPath)
	if err != nil {
		if _, statErr := os.Lstat(receiptPath); !os.IsNotExist(statErr) {
			return fail
		}
		for _, name := range []string{"result.json", "diagnostic.json"} {
			if _, statErr := os.Lstat(filepath.Join(stage, name)); !os.IsNotExist(statErr) {
				return fail
			}
		}
		// The controller publishes its running receipt before invoking Ansible.
		// A prepared stage without a receipt therefore records only local setup;
		// it never authorized external effects and must be replaced by a fresh
		// full-fleet census before any handoff can be published.
		return nil
	}
	var receipt struct {
		Schema     int                       `json:"schema_version"`
		Operation  string                    `json:"operation"`
		RequestSHA string                    `json:"request_sha256"`
		BinarySHA  string                    `json:"binary_sha256"`
		State      string                    `json:"state"`
		Code       string                    `json:"code"`
		ExitCode   *int                      `json:"exit_code"`
		Diagnostic *deployansible.Diagnostic `json:"diagnostic"`
		StartedAt  *int64                    `json:"started_at"`
		FinishedAt *int64                    `json:"finished_at"`
		Result     map[string]any            `json:"result"`
	}
	if decodeForwardChain(receiptRaw, &receipt) != nil || receipt.Schema != 1 || receipt.Operation != "drain-upgrade-workers" ||
		receipt.RequestSHA != requestSHA || receipt.BinarySHA != requestSHA || receipt.Result != nil ||
		receipt.StartedAt == nil || *receipt.StartedAt <= 0 {
		return fail
	}
	if _, err := os.Lstat(filepath.Join(stage, "result.json")); !os.IsNotExist(err) {
		return fail
	}
	diagnosticPath := filepath.Join(stage, "diagnostic.json")
	diagnosticRaw, diagnosticErr := readForwardEvidence(diagnosticPath)
	_, diagnosticLstatErr := os.Lstat(diagnosticPath)
	diagnosticAbsent := os.IsNotExist(diagnosticLstatErr)
	switch receipt.State {
	case "failed":
		if receipt.FinishedAt == nil || *receipt.FinishedAt < *receipt.StartedAt {
			return fail
		}
		switch receipt.Code {
		case "ansible_failed":
			if receipt.ExitCode == nil || *receipt.ExitCode < 1 || *receipt.ExitCode > 255 {
				return fail
			}
			if receipt.Diagnostic == nil {
				if !diagnosticAbsent {
					return fail
				}
			} else {
				var saved deployansible.Diagnostic
				if diagnosticErr != nil || decodeForwardChain(diagnosticRaw, &saved) != nil || saved != *receipt.Diagnostic {
					return fail
				}
			}
		case "execution_failed":
			if receipt.ExitCode != nil || receipt.Diagnostic != nil || !diagnosticAbsent {
				return fail
			}
		default:
			return fail
		}
	case "running":
		if (receipt.Code != "" && receipt.Code != "interrupted") || receipt.ExitCode != nil || receipt.Diagnostic != nil ||
			receipt.FinishedAt != nil ||
			!diagnosticAbsent {
			return fail
		}
	default:
		return fail
	}
	return nil
}

func forwardUpgradeChainedHandoff(
	ctx context.Context,
	proof forwardUpgradeJournal,
	old forwardOldOperation,
	root, directory, python, executable string,
	prior forwardPriorCandidate,
	deps forwardHandoffDeps,
) (context.Context, func(), error) {
	fail := errors.New("upgrade_forward_chain_unverified")
	if operatorPrivate(root, true) != nil || operatorPrivate(directory, true) != nil || filepath.Dir(directory) != root ||
		prior.Directory == directory ||
		prior.Directory == old.Directory {
		return ctx, nil, fail
	}
	verified, err := discoverForwardOldOperation(proof, root)
	if err != nil || verified.ID != old.ID || !sameForwardJSON(verified.Inventory, old.Inventory) {
		return ctx, nil, fail
	}
	if err := verifyForwardPostHandoffCandidate(proof, old, root, directory, prior); err != nil {
		return ctx, nil, err
	}
	fingerprint, err := forwardCandidateFingerprint(prior.Directory)
	if err != nil {
		return ctx, nil, err
	}
	handoff, err := readForwardEvidence(filepath.Join(prior.Directory, "forward-handoff.json"))
	if err != nil {
		return ctx, nil, err
	}
	currentRaw, err := readForwardEvidence(filepath.Join(root, "lifecycle-retired.json"))
	if err != nil {
		return ctx, nil, err
	}
	var state struct {
		ID    string `json:"id"`
		Phase string `json:"phase"`
	}
	stateRaw, err := readForwardEvidence(filepath.Join(root, "lifecycle.json"))
	if err != nil || decodeForwardChain(stateRaw, &state) != nil || state.Phase != "applying" {
		return ctx, nil, fail
	}
	originalEvidence, err := forwardOriginalEvidence(proof, old)
	if err != nil {
		return ctx, nil, err
	}
	expected := forwardChainIntent{
		OriginalEvidenceSHA: originalEvidence,
		Schema:              1,
		ProofSHA:            proof.SHA256,
		PriorJournalSHA:     prior.SHA256,
		OriginalID:          old.ID,
		PriorID:             lifecycleID(prior.Directory),
		NewID:               lifecycleID(directory),
		PriorEvidenceSHA:    fingerprint,
		OriginalHandoffSHA:  digestSHA256(handoff),
	}
	path := filepath.Join(directory, "forward-chain.json")
	savedRaw, readErr := readForwardEvidence(path)
	var saved forwardChainIntent
	if readErr == nil {
		if decodeForwardChain(savedRaw, &saved) != nil {
			return ctx, nil, fail
		}
		expected.OriginalRetirementJSON = saved.OriginalRetirementJSON
		expected.OriginalRetirementSHA = saved.OriginalRetirementSHA
	} else if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return ctx, nil, fail
	} else {
		expected.OriginalRetirementJSON = string(currentRaw)
		expected.OriginalRetirementSHA = digestSHA256(currentRaw)
	}
	if digestSHA256([]byte(expected.OriginalRetirementJSON)) != expected.OriginalRetirementSHA {
		return ctx, nil, fail
	}
	originalLedger, err := checkForwardChainLedger([]byte(expected.OriginalRetirementJSON), old.ID, expected.PriorID)
	if err != nil {
		return ctx, nil, err
	}
	for _, id := range originalLedger.IDs {
		if id == expected.NewID {
			return ctx, nil, fail
		}
	}
	if readErr == nil && saved != expected {
		return ctx, nil, errors.New("upgrade_forward_chain_changed")
	}
	predecessor := forwardOldOperation{Directory: prior.Directory, ID: expected.PriorID, Inventory: old.Inventory}
	if err := verifyForwardChainDestination(proof, predecessor, root, directory, deps.archive); err != nil {
		return ctx, nil, err
	}
	// A successful containment receipt proves shutdown only. It does not carry
	// the original bot/timer states or physical database baseline required to
	// inspect and prepare B while A remains stopped. Ordinary upgrade preflight
	// requires active services, so superseding A here would retire its recovery
	// authority before a deterministic failure. A dedicated stopped-service
	// protocol must be implemented before this transition can be enabled.
	return ctx, nil, errors.New("upgrade_forward_contained_continuation_unavailable")
}

func verifyForwardPostHandoffCandidate(
	proof forwardUpgradeJournal,
	old forwardOldOperation,
	root, directory string,
	prior forwardPriorCandidate,
) error {
	fail := errors.New("upgrade_forward_prior_candidate_unverified")
	if operatorPrivate(prior.Directory, true) != nil || prior.Directory == directory || prior.Directory == old.Directory ||
		!filepath.IsAbs(prior.Directory) ||
		filepath.Clean(prior.Directory) != prior.Directory ||
		filepath.Dir(prior.Directory) != root ||
		prior.Journal != filepath.Join(filepath.Dir(proof.Path), "forward-prior-operation.json") ||
		!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(prior.SHA256) {
		return fail
	}
	for _, path := range []string{prior.Directory, prior.Journal, proof.Path} {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || resolved != path {
			return fail
		}
	}
	raw, err := readForwardEvidence(prior.Journal)
	if err != nil || digestSHA256(raw) != prior.SHA256 {
		return fail
	}
	var journal struct {
		Schema        int                  `json:"schema"`
		Commit        string               `json:"commit"`
		Version       string               `json:"version"`
		Attempt       string               `json:"remote_attempt"`
		Stage         string               `json:"stage"`
		Dispatched    bool                 `json:"mutator_dispatched"`
		Forward       bool                 `json:"forward_only"`
		ProofSHA      string               `json:"forward_journal_sha256"`
		ConfigSHA     string               `json:"staged_config_sha256"`
		SecretsSource journalSecretsSource `json:"secrets_source"`
		ManifestSHA   string               `json:"manifest_sha256"`
	}
	if json.Unmarshal(raw, &journal) != nil || journal.Schema != 1 || !journal.Dispatched || !journal.Forward ||
		journal.Stage != "upgrade" ||
		journal.ProofSHA != proof.SHA256 ||
		!regexp.MustCompile(`^[a-f0-9]{40}$`).MatchString(journal.Commit) ||
		!regexp.MustCompile(`^[a-f0-9]{64}$`).MatchString(journal.Attempt) ||
		prior.Directory != filepath.Join(root, "upgrade-"+journal.Version) {
		return fail
	}
	input := filepath.Join(root, "operator-inputs", "manual-"+journal.Commit+"-"+journal.Attempt)
	if resolved, err := filepath.EvalSymlinks(input); err != nil || resolved != input || operatorPrivate(input, true) != nil {
		return fail
	}
	config := filepath.Join(input, "install.config")
	configRaw, err := readForwardEvidence(config)
	if err != nil || digestSHA256(configRaw) != journal.ConfigSHA {
		return fail
	}
	plan, err := installplan.LoadLifecycleConfig(config)
	if err == nil {
		err = bindVerificationSecretsSource(plan, string(journal.SecretsSource))
	}
	release := filepath.Join(input, "release")
	if err != nil || installplan.ValidatePlan(plan) != nil || plan.Automation == nil || plan.Automation.Version != journal.Version ||
		plan.Automation.ReleaseDir != release ||
		matchOperatorPlan(prior.Directory, plan, release) != nil {
		return fail
	}
	if operatorPrivate(release, true) != nil {
		return fail
	}
	releaseEntries, err := os.ReadDir(release)
	if err != nil {
		return fail
	}
	for _, entry := range releaseEntries {
		if operatorPrivate(filepath.Join(release, entry.Name()), false) != nil {
			return fail
		}
	}
	priorManifest, err := verifyOperatorUpgradeRelease(
		release,
		journal.Commit,
		journal.Version,
		journal.ManifestSHA,
		filepath.Join(release, "ultra-install-linux-"+runtime.GOARCH),
	)
	if err != nil {
		return fail
	}
	modeRaw, err := readForwardEvidence(filepath.Join(prior.Directory, "execution-mode.json"))
	var mode frozenExecution
	if err != nil || json.Unmarshal(modeRaw, &mode) != nil || mode.Schema != 1 || !mode.Local || mode.Native ||
		mode.LockDirectory != root ||
		mode.OperatorDirectory != filepath.Join(root, "operator") ||
		mode.Target != plan.Bridge.SSHHost+"|"+plan.Bridge.Address {
		return fail
	}
	// Exact lifecycle ownership is separately proven against the preserved O->A ledger and current A->B ledger.
	postArtifacts, err := verifyForwardPostHandoffArtifacts(old, root, prior.Directory, release, plan)
	if err != nil {
		return fail
	}
	entries, err := os.ReadDir(prior.Directory)
	if err != nil {
		return fail
	}
	drains := 0
	hasIntent := false
	for _, entry := range entries {
		path := filepath.Join(prior.Directory, entry.Name())
		if postArtifacts[entry.Name()] {
			continue
		}
		switch entry.Name() {
		case "runtime-use.json":
			if verifyForwardRuntimeUse(path, root, priorManifest) != nil {
				return fail
			}
		case "forward-handoff.json":
			if verifyForwardIntent(proof, old, root, prior.Directory) != nil {
				return fail
			}
			hasIntent = true
		case "execution-mode.json", "operator-plan.json":
			if _, err := readForwardEvidence(path); err != nil {
				return fail
			}
		default:
			if strings.HasPrefix(entry.Name(), "broker-bootstrap-") {
				variables, err := forwardBootstrapVariables(old, priorManifest, root, prior.Directory, release)
				result := map[string]any{
					"verified":             true,
					"old_id":               old.ID,
					"controller_directory": managedControllerDirectory(priorManifest.Version),
				}
				if err != nil {
					return fail
				}
				if _, err := verifyForwardSavedStage(path, filepath.Join(release, "ultra-ansible.tar.gz"), "bootstrap-forward-broker", old.Inventory, variables, result, nil); err != nil {
					return fail
				}

				continue
			}
			if !strings.HasPrefix(entry.Name(), "handoff-drain-") || operatorPrivate(path, true) != nil {
				return fail
			}
			if _, err := forwardDrainIntent(proof, old, root, prior.Directory, path); err != nil {
				return fail
			}
			if err := verifyForwardDrainFiles(path, filepath.Join(release, "ultra-ansible.tar.gz")); err != nil {
				return fail
			}
			drains++
		}
	}
	// This protocol requires a completed O->A intent. Pre-handoff recovery
	// remains governed by the separate, unchanged prior-candidate validator.
	if !hasIntent || drains == 0 {
		return fail
	}
	return nil
}
