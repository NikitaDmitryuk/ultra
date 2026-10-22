package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type operatorJournalInspection struct {
	Protocol       string            `json:"protocol"`
	State          string            `json:"state"`
	JournalSHA256  string            `json:"journal_sha256"`
	ConfigSHA256   string            `json:"config_sha256"`
	RemoteEvidence map[string]string `json:"remote_evidence_sha256"`
	NextAction     string            `json:"next_action"`
	MayAbandon     bool              `json:"may_abandon"`
}

// A report is observation, never an authority to dispatch. The only changing
// action delegates to the existing exact, bridge-only non-dispatch protocol.
func runOperatorJournalReconcile(args []string, out io.Writer) error {
	if len(args) == 0 || (args[0] != "inspect" && args[0] != "abandon-undispatched") {
		return errors.New("operator_journal_action_required")
	}
	fs := flag.NewFlagSet("operator-journal-reconcile", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config := fs.String("config", "", "canonical operator config")
	journal := fs.String("original-journal", "", "original journal preserved unchanged")
	state := fs.String("state-dir", "", "retained recovery workspace, if applicable")
	manifest := fs.String("manifest", "", "original retained recovery release manifest")
	receipt := fs.String("receipt", "", "new evidence file for abandonment")
	confirmation := fs.String("confirm-journal-sha256", "", "explicit acknowledgement of exact journal for abandonment")
	if fs.Parse(args[1:]) != nil || fs.NArg() != 0 {
		return errors.New("operator_journal_arguments_invalid")
	}
	for _, path := range []string{*config, *journal} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return errors.New("operator_journal_absolute_paths_required")
		}
	}
	for _, path := range []string{*state, *manifest, *receipt} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return errors.New("operator_journal_absolute_paths_required")
		}
	}
	if (*state == "") != (*manifest == "") {
		return errors.New("operator_journal_retained_inputs_required")
	}
	if *state != "" || args[0] == "abandon-undispatched" {
		if err := requireRootOperator(); err != nil {
			return err
		}
	}
	lock, err := openOperatorLock(
		filepath.Join(filepath.Dir(*config), "."+filepath.Base(*config)+".manual-deploy.lock"),
		uint32(os.Geteuid()),
	)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	raw, err := readRebuildInput(*journal, true)
	if err != nil {
		return err
	}
	if args[0] == "abandon-undispatched" {
		if *state == "" || *receipt == "" || !rebuildSHA.MatchString(*confirmation) || *confirmation != digestSHA256(raw) {
			return errors.New("operator_journal_explicit_confirmation_required")
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		ctx, timeout := context.WithTimeout(ctx, 3*time.Minute)
		defer timeout()
		return abandonRetainedUndispatchedAdmission(ctx, out, *state, *config, *manifest, *journal, *receipt)
	}
	if *receipt != "" || *confirmation != "" {
		return errors.New("operator_journal_inspect_read_only")
	}
	// Re-read after acquiring the shared admission lock.
	raw, err = readRebuildInput(*journal, true)
	if err != nil {
		return err
	}
	configRaw, err := readRebuildInput(*config, true)
	if err != nil {
		return err
	}
	report, err := classifyOperatorJournal(raw, configRaw)
	if err != nil {
		return err
	}
	p, err := installplan.LoadConfig(*config)
	if err != nil || p.Automation == nil {
		return errors.New("operator_journal_config_invalid")
	}
	if p.SSH.User != "root" {
		return errors.New("operator_root_transport_required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, timeout := context.WithTimeout(ctx, 5*time.Minute)
	defer timeout()
	report.RemoteEvidence, err = observeOperatorJournal(ctx, p)
	if err != nil {
		return err
	}
	if *state != "" {
		in, _, e := verifyRetainedUndispatchedWorkspace(*state, *config, *manifest, *journal)
		if e == nil && retainedInventoryHost(in, "bridge", "bridge")["ansible_host"] == p.Bridge.SSHHost {
			if e = retainedLocalCensus(); e != nil {
				return e
			}
			lease, e := openRetainedAbandonLease(ctx, p, in.FenceEvidenceSHA256)
			if e != nil {
				return e
			}
			// EOF releases the read-only proof lease; it never authorizes abandon.
			lease.close()
			report.State = "retained_undispatched_verified"
			report.NextAction = "operator-journal-reconcile abandon-undispatched"
			report.MayAbandon = true
		} else {
			report.NextAction = "retained-primary-reconcile inspect"
		}
	}
	current, err := readRebuildInput(*journal, true)
	if err != nil || digestSHA256(current) != report.JournalSHA256 {
		return errors.New("operator_journal_inputs_changed")
	}
	current, err = readRebuildInput(*config, true)
	if err != nil || digestSHA256(current) != report.ConfigSHA256 {
		return errors.New("operator_journal_inputs_changed")
	}
	return json.NewEncoder(out).Encode(report)
}

func classifyOperatorJournal(raw, config []byte) (operatorJournalInspection, error) {
	report := operatorJournalInspection{Protocol: "ultra-operator-journal-inspection-v1", State: "blocked_unknown",
		JournalSHA256: digestSHA256(raw), ConfigSHA256: digestSHA256(config), NextAction: "manual-deploy supported recovery inspection"}
	var record map[string]json.RawMessage
	if retainedReconcileUniqueJSON(raw) != nil || json.Unmarshal(raw, &record) != nil || record == nil {
		return report, errors.New("operator_journal_invalid")
	}
	var bound string
	if value, ok := record["config_sha256"]; ok {
		if json.Unmarshal(value, &bound) != nil || bound != report.ConfigSHA256 {
			return report, errors.New("operator_journal_config_binding_changed")
		}
	}
	var dispatched bool
	if value, ok := record["mutator_dispatched"]; ok {
		if string(value) != "true" && string(value) != "false" {
			return report, errors.New("operator_journal_invalid")
		}
		_ = json.Unmarshal(value, &dispatched)
	}
	var stage string
	_ = json.Unmarshal(record["stage"], &stage)
	if dispatched && stage == "upgrade" {
		report.NextAction = "manual-deploy --forward-only (independent admission required)"
	}
	// Even false/missing dispatch fields, a terminal-looking stage or empty
	// remote directories are not independently authenticated completion proof.
	return report, nil
}

func observeOperatorJournal(ctx context.Context, p *installplan.InstallPlan) (map[string]string, error) {
	proof := map[string]string{}
	targets := []struct{ role, address, key string }{{"bridge", p.Bridge.SSHHost, p.BridgeSSHIdentity()}}
	for _, exit := range p.Exits {
		targets = append(targets, struct{ role, address, key string }{"exit", exit.SSHHost, p.ExitSSHIdentity(exit)})
	}
	for i, target := range targets {
		raw, err := retainedRemote(ctx, p, target.address, target.key, false, operatorJournalObservation, nil)
		if err != nil {
			return nil, err
		}
		var evidence struct {
			Protocol string            `json:"protocol"`
			Files    map[string]string `json:"files"`
		}
		if decodeRetainedReconcile(raw, &evidence) != nil || evidence.Protocol != "ultra-journal-observation-v1" ||
			len(evidence.Files) != 3 {
			return nil, errors.New("operator_journal_remote_evidence_invalid")
		}
		for _, name := range []string{"execution-fence.json", "retained-primary-admission.json", "recovery-fence.json"} {
			value := evidence.Files[name]
			if value != "absent" && !rebuildSHA.MatchString(value) {
				return nil, errors.New("operator_journal_remote_evidence_invalid")
			}
		}
		proof[target.role+"-"+strconv.Itoa(i)] = digestSHA256(raw)
	}
	return proof, nil
}

const operatorJournalObservation = `import os,stat,hashlib,json
root='/var/lib/ultra-ansible'
files={}
for name in ['execution-fence.json','retained-primary-admission.json','recovery-fence.json']:
 path=root+'/'+name
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 except FileNotFoundError:
  files[name]='absent';continue
 try:
  s=os.fstat(fd)
  assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600 and s.st_size<=1048576
  raw=os.read(fd,1048577);assert len(raw)<=1048576
  files[name]=hashlib.sha256(raw).hexdigest()
 finally:os.close(fd)
print(json.dumps({'protocol':'ultra-journal-observation-v1','files':files},sort_keys=True))
`
