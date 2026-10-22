package main

// A one-shot admission whose attempt never dispatched cannot be reconciled:
// reconciliation observes a successful execute, and this attempt has none. This
// command proves non-dispatch from the local workspace and the remote fence, then
// retires the claim as preserved evidence. It never unlinks the marker, never
// touches the retained exit, and never dispatches Ansible.
import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

const retainedUndispatchedProtocol = "ultra-retained-primary-undispatched-v1"

// prepareLocalOperation writes exactly these four entries. A fifth entry is
// either a dispatch claim or a receipt, and both forbid abandonment.
const retainedUndispatchedEntries = "bundle,bundle.retention.json,job.json,request.json"

type retainedUndispatchedAbandonment struct {
	Protocol                string `json:"protocol"`
	StateDirectory          string `json:"state_directory"`
	PreparedSHA256          string `json:"prepared_sha256"`
	RequestSHA256           string `json:"request_sha256"`
	JobSHA256               string `json:"job_sha256"`
	BundleSealSHA256        string `json:"bundle_seal_sha256"`
	ConfigSHA256            string `json:"config_sha256"`
	ManifestSHA256          string `json:"manifest_sha256"`
	JournalSHA256           string `json:"journal_sha256"`
	BindingSHA256           string `json:"binding_sha256"`
	FenceEvidenceSHA256     string `json:"fence_evidence_sha256"`
	RetainedExitFenceSHA256 string `json:"retained_exit_fence_sha256"`
	MarkerSHA256            string `json:"marker_sha256"`
	AbandonedMarker         string `json:"abandoned_marker"`
	Dispatched              bool   `json:"dispatched"`
	Abandoned               bool   `json:"abandoned"`
}

// The marker is renamed, never removed: the durable claim and its exact binding
// stay readable after the fleet is unfenced.
func abandonRetainedUndispatchedAdmission(
	ctx context.Context,
	out io.Writer,
	directory, config, manifest, journal, receipt string,
) error {
	in, artifacts, err := verifyRetainedUndispatchedWorkspace(directory, config, manifest, journal)
	if err != nil {
		return err
	}
	p, err := installplan.LoadConfig(config)
	if err != nil || p.Automation == nil || len(p.Exits) != 1 {
		return errors.New("retained_abandon_config_invalid")
	}
	// The abandoned workspace must belong to this bridge. A stale workspace for a
	// different host would retire an admission that is still the only record of a
	// live claim.
	if retainedInventoryHost(in, "bridge", "bridge")["ansible_host"] != p.Bridge.SSHHost {
		return errors.New("retained_abandon_target_mismatch")
	}
	if err = retainedLocalCensus(); err != nil {
		return err
	}
	lease, err := openRetainedAbandonLease(ctx, p, in.FenceEvidenceSHA256)
	if err != nil {
		return err
	}
	defer lease.close()
	marker, err := lease.abandon()
	if err != nil {
		return err
	}
	result, marshalErr := json.Marshal(retainedUndispatchedAbandonment{
		Protocol:                retainedUndispatchedProtocol,
		StateDirectory:          directory,
		PreparedSHA256:          artifacts["prepared"],
		RequestSHA256:           artifacts["request"],
		JobSHA256:               artifacts["job"],
		BundleSealSHA256:        artifacts["bundle_receipt"],
		ConfigSHA256:            in.ConfigSHA256,
		ManifestSHA256:          in.ManifestSHA256,
		JournalSHA256:           in.JournalSHA256,
		BindingSHA256:           in.FenceEvidenceSHA256,
		FenceEvidenceSHA256:     in.FenceEvidenceSHA256,
		RetainedExitFenceSHA256: in.RetainedExit.FenceSHA256,
		MarkerSHA256:            marker,
		AbandonedMarker:         "retained-primary-admission.abandoned-" + marker + ".json",
		Dispatched:              false,
		Abandoned:               true,
	})
	if marshalErr != nil {
		return errors.New("retained_abandon_receipt_unencodable")
	}
	if err = publishRetainedReconcile(receipt, result); err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		out,
		"retained-primary admission abandoned as undispatched; marker_sha256=%s; evidence_sha256=%s\n",
		marker,
		digestSHA256(result),
	)
	return err
}

// Reuses the historical two serializers of the recovery binding, so an attempt
// that dispatched under either one is still recognized as dispatched.
func verifyRetainedUndispatchedWorkspace(
	directory, config, manifest, journal string,
) (retainedPrimaryRebuildInput, map[string]string, error) {
	var in retainedPrimaryRebuildInput
	artifacts := map[string]string{}
	read := func(name, path string, private bool) ([]byte, error) {
		raw, err := readRebuildInput(path, private)
		if err == nil {
			artifacts[name] = digestSHA256(raw)
		}
		return raw, err
	}
	raw, err := read("prepared", filepath.Join(directory, "prepared-input.json"), true)
	if err != nil {
		return in, artifacts, errors.New("retained_abandon_prepared_unavailable")
	}
	if err = decodeRetainedReconcile(raw, &in); err != nil {
		return in, artifacts, errors.New("retained_abandon_prepared_invalid")
	}
	physical := in
	physical.Directory = directory
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory ||
		in.Directory != directory || validateRetainedPrimaryRebuild(physical) != nil {
		return in, artifacts, errors.New("retained_abandon_prepared_invalid")
	}
	// Only a bridge-scoped attempt may be abandoned here. A two-host attempt
	// claimed the retained exit with this same binding, so retiring the bridge
	// marker alone would leave that exit permanently fenced with no local record.
	if !in.BridgeOnly || in.RetainedExit == nil || !in.RetainedExit.valid() ||
		in.RetainedExit.FenceSHA256 == in.FenceEvidenceSHA256 {
		return in, artifacts, errors.New("retained_abandon_scope_not_bridge_only")
	}
	for _, a := range []struct {
		name, path, hash string
		private          bool
	}{
		{"config", config, in.ConfigSHA256, true},
		{"manifest", manifest, in.ManifestSHA256, false},
		{"journal", journal, in.JournalSHA256, true},
	} {
		value, readErr := read(a.name, a.path, a.private)
		if readErr != nil || digestSHA256(value) != a.hash {
			return in, artifacts, errors.New("retained_abandon_original_changed")
		}
	}
	execute := filepath.Join(directory, "execute")
	entries, err := os.ReadDir(execute)
	if err != nil {
		return in, artifacts, errors.New("retained_abandon_execute_unavailable")
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if strings.Join(names, ",") != retainedUndispatchedEntries {
		return in, artifacts, errors.New("retained_abandon_workspace_dispatched")
	}
	request, err := read("request", filepath.Join(execute, "request.json"), true)
	if err != nil {
		return in, artifacts, err
	}
	var submitted struct {
		ExecutionTimeoutSeconds *int64         `json:"execution_timeout_seconds,omitempty"`
		Inventory               map[string]any `json:"inventory"`
		Variables               map[string]any `json:"variables"`
	}
	if decodeRetainedReconcile(request, &submitted) != nil {
		return in, artifacts, errors.New("retained_abandon_request_changed")
	}
	if !retainedExecutionTimeoutMatches(in.ExecutionTimeoutSeconds, submitted.ExecutionTimeoutSeconds) {
		return in, artifacts, errors.New("retained_abandon_execution_timeout_changed")
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return in, artifacts, errors.New("retained_abandon_prepared_invalid")
	}
	normalized, _ := json.Marshal(in)
	binding, ok := submitted.Variables["ultra_retained_recovery_binding_sha256"].(string)
	if !ok || (binding != digestSHA256(compact.Bytes()) && binding != digestSHA256(normalized)) {
		return in, artifacts, errors.New("retained_abandon_binding_invalid")
	}
	job, err := read("job", filepath.Join(execute, "job.json"), true)
	if err != nil {
		return in, artifacts, err
	}
	var saved map[string]any
	if retainedReconcileUniqueJSON(job) != nil || json.Unmarshal(job, &saved) != nil || saved["schema_version"] != float64(1) ||
		saved["operation"] != retainedRebuildOperation(in) ||
		saved["request_sha256"] != artifacts["request"] ||
		saved["binary_sha256"] != artifacts["request"] {
		return in, artifacts, errors.New("retained_abandon_execute_identity_invalid")
	}
	seal, err := read("bundle_receipt", filepath.Join(execute, "bundle.retention.json"), true)
	if err != nil {
		return in, artifacts, err
	}
	if err = verifyRetainedReconcileBundleSnapshot(
		filepath.Join(execute, "bundle"),
		filepath.Join(directory, "execute", "bundle"),
		seal,
		artifacts["request"],
	); err != nil {
		return in, artifacts, err
	}
	return in, artifacts, nil
}

type retainedAbandonLease struct {
	cmd     *exec.Cmd
	input   io.WriteCloser
	scanner *bufio.Scanner
}

func openRetainedAbandonLease(
	ctx context.Context,
	p *installplan.InstallPlan,
	binding string,
) (*retainedAbandonLease, error) {
	args := retainedSSH(p, p.Bridge.SSHHost, p.BridgeSSHIdentity(), false, true, "mutate")
	args = append(
		args,
		strings.Join(
			quoteRetainedArgs([]string{"python3", "-u", "-c", retainedAbandonProgram, binding}),
			" ",
		),
	)
	c := exec.CommandContext(ctx, args[0], args[1:]...)
	input, err := c.StdinPipe()
	if err != nil {
		return nil, errors.New("retained_abandon_lease_start_failed")
	}
	output, err := c.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, errors.New("retained_abandon_lease_start_failed")
	}
	l := &retainedAbandonLease{c, input, bufio.NewScanner(output)}
	if err = c.Start(); err != nil {
		_ = input.Close()
		return nil, errors.New("retained_abandon_lease_start_failed")
	}
	if !l.scanner.Scan() || l.scanner.Text() != "verified" {
		l.close()
		return nil, errors.New("retained_abandon_remote_preflight_failed")
	}
	return l, nil
}

func (l *retainedAbandonLease) close() { _ = l.input.Close(); _ = l.cmd.Wait() }

func (l *retainedAbandonLease) abandon() (string, error) {
	if _, err := io.WriteString(l.input, "abandon\n"); err != nil {
		return "", errors.New("retained_abandon_unverified")
	}
	if !l.scanner.Scan() || l.scanner.Text() != "abandoned" || !l.scanner.Scan() {
		return "", errors.New("retained_abandon_unverified")
	}
	var proof struct {
		MarkerSHA256 string `json:"marker_sha256"`
	}
	if json.Unmarshal(l.scanner.Bytes(), &proof) != nil || !rebuildSHA.MatchString(proof.MarkerSHA256) {
		return "", errors.New("retained_abandon_unverified")
	}
	return proof.MarkerSHA256, nil
}

// Both admission locks stay held across the second proof and the whole mutation.
// EOF or a killed operator never means "abandoned".
const retainedAbandonProgram = `import os,sys,stat,json,fcntl,subprocess,hashlib
from pathlib import Path
binding=sys.argv[1]
state=Path('/var/lib/ultra-ansible')
system=Path('/etc/systemd/system')
dropin='[Unit]\nRefuseManualStart=yes\nConditionPathExists=/var/lib/ultra-ansible/retained-primary-admission-open\n'
units=['ultra-ansible-controller.service','ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']
raw=None
def trusted(path,directory=False,private=False):
 p=Path(path)
 for ancestor in [p]+list(p.parents):
  s=ancestor.lstat()
  assert s.st_uid==0 and not s.st_mode&0o022 and not stat.S_ISLNK(s.st_mode)
 s=p.lstat()
 assert stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink==1
 if private:assert stat.S_IMODE(s.st_mode)==0o600
 return p
def show(unit):
 r=subprocess.run(['systemctl','show',unit,'--property=LoadState','--property=ActiveState','--property=RefuseManualStart'],capture_output=True,text=True,timeout=10)
 assert r.returncode in [0,1]
 return dict(line.split('=',1) for line in r.stdout.splitlines() if '=' in line)
def census():
 for proc in Path('/proc').iterdir():
  if not proc.name.isdigit() or int(proc.name)==os.getpid():continue
  try:args=(proc/'cmdline').read_bytes().split(b'\0')
  except (FileNotFoundError,ProcessLookupError):continue
  names=[os.path.basename(x.decode(errors='replace')) for x in args]
  assert not any(x in ['ultra-install','ansible-playbook','controller.py','reconcile.py','retained-primary-reconcile','rebuild-retained-primary'] for x in names)
def prove():
 global raw
 trusted(state,True)
 marker=trusted(state/'retained-primary-admission.json',private=True)
 raw=marker.read_bytes()
 assert json.loads(raw)=={'protocol':'retained-primary-admission-v1','binding_sha256':binding}
 assert not os.path.lexists(state/'retained-primary-admission-open')
 # Separate protocols with deliberately unsupported completion stay untouched.
 assert not os.path.lexists(state/'recovery-fence.json')
 assert not os.path.lexists(state/'recovery-anchor.json')
 for unit in units:
  p=trusted(system/(unit+'.d/90-retained-primary.conf'))
  assert p.read_text()==dropin
  properties=show(unit)
  assert properties.get('ActiveState') in ['inactive','failed']
  if properties.get('LoadState')=='loaded':assert properties.get('RefuseManualStart')=='yes'
 census()
locks=[]
for path in [state/'infrastructure.lock',state/'operator-inputs/manual-deploy.lock']:
 trusted(path,private=True)
 fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(fd)
prove()
print('verified',flush=True)
command=sys.stdin.readline()
if not command:sys.exit(0)
assert command=='abandon\n'
prove()
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
digest=hashlib.sha256(raw).hexdigest()
retired=state/('retained-primary-admission.abandoned-'+digest+'.json')
assert not os.path.lexists(retired)
os.replace(state/'retained-primary-admission.json',retired)
syncdir(state)
for unit in units:
 p=system/(unit+'.d/90-retained-primary.conf')
 if p.read_text()==dropin:os.unlink(p)
 syncdir(p.parent)
subprocess.run(['systemctl','daemon-reload'],check=True,timeout=20)
assert not os.path.lexists(state/'retained-primary-admission.json')
assert trusted(retired,private=True).read_bytes()==raw
for unit in units:assert not os.path.lexists(system/(unit+'.d/90-retained-primary.conf'))
print('abandoned',flush=True)
print(json.dumps({'marker_sha256':digest}),flush=True)
sys.stdin.buffer.read()
`
