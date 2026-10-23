package main

// A failed generation that produced a receipt but no completion proof can never
// be reconciled: normal completion is the only automatic proof. This action
// retires exactly that generation and the remote admission it claimed, only after
// proving locally and on both hosts that no executor of it survives. Every
// original byte stays readable as evidence, and nothing here is a completion.
// The exit carries the admission of the earlier retained rebuild, not this
// generation's claim, so it is proven and preserved: the next attempt needs it.
import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

const retainedRetirementProtocol = "ultra-retained-execution-retirement-v1"

type retainedRetiredExecution struct {
	Protocol        string `json:"protocol"`
	StateDirectory  string `json:"state_directory"`
	Generation      string `json:"generation"`
	Operation       string `json:"operation"`
	JobSHA256       string `json:"job_sha256"`
	RequestSHA256   string `json:"request_sha256"`
	BundleSHA256    string `json:"bundle_sha256"`
	ReceiptSHA256   string `json:"receipt_sha256"`
	DispatchSHA256  string `json:"dispatch_sha256"`
	ConfigSHA256    string `json:"config_sha256"`
	ManifestSHA256  string `json:"manifest_sha256"`
	JournalSHA256   string `json:"journal_sha256"`
	BindingSHA256   string `json:"binding_sha256"`
	BridgeMarkerSHA string `json:"bridge_marker_sha256"`
	ExitMarkerSHA   string `json:"exit_marker_sha256"`
	AttestedAt      int64  `json:"attested_at"`
}

// retireFailedRetainedExecution performs the whole retirement in one order, so a
// half-retired fleet cannot be produced by calling the halves out of order.
func retireFailedRetainedExecution(
	ctx context.Context,
	out io.Writer,
	directory, config, manifest, journal, receipt string,
) error {
	in, fence, err := verifyRetainedFailedWorkspace(directory, config, manifest, journal)
	if err != nil {
		return err
	}
	p, err := installplan.LoadConfig(config)
	if err != nil || p.Automation == nil || len(p.Exits) != 1 {
		return errors.New("retained_retire_config_invalid")
	}
	// Census first: no local runner may be able to continue the attempt.
	if err = retainedLocalCensus(); err != nil {
		return err
	}
	leases, err := openRetainedRetirementLeases(ctx, p, in, fence.Generation)
	if err != nil {
		return err
	}
	defer func() {
		for _, l := range leases {
			l.close()
		}
	}()
	prove := func(expected deployansible.ExecutionFence) error {
		if proveErr := deployansible.ProveFailedExecutionQuiescent(expected); proveErr != nil {
			return proveErr
		}
		// Repeated here, under the local admission lock, so quiescence is
		// attested at the moment of retirement and not only on arrival.
		for _, l := range leases {
			if proveErr := l.prove(); proveErr != nil {
				return proveErr
			}
		}
		return nil
	}
	if err = deployansible.AbandonExecutionFence(fence, prove); err != nil {
		return err
	}
	// Only the bridge received this generation's admission: in bridge-only scope
	// every mutation target is the bridge. The exit's marker predates the attempt
	// and is what the next attempt still requires, so it is proved and preserved
	// unchanged. Retiring it would hand back an unfenced fleet.
	markers := map[string]string{}
	for _, l := range leases {
		var marker string
		var markerErr error
		if l.role == "bridge" {
			marker, markerErr = l.abandon()
		} else {
			marker, markerErr = l.preserve()
		}
		if markerErr != nil {
			return markerErr
		}
		markers[l.role] = marker
	}
	record, err := retainedRetirementRecord(directory, in, fence, markers)
	if err != nil {
		return err
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return errors.New("retained_retire_receipt_unencodable")
	}
	if err = publishRetainedReconcile(receipt, raw); err != nil {
		return err
	}
	_, err = fmt.Fprintf(
		out,
		"failed generation retired as preserved evidence; generation=%s; evidence_sha256=%s; a new workspace is required to continue\n",
		fence.Generation, digestSHA256(raw),
	)
	return err
}

// The record repeats the digests the abandonment itself preserved, so the receipt
// and the local evidence can be compared byte for byte later.
func retainedRetirementRecord(
	directory string,
	in retainedPrimaryRebuildInput,
	fence deployansible.ExecutionFence,
	markers map[string]string,
) (retainedRetiredExecution, error) {
	var record retainedRetiredExecution
	saved, err := readRebuildInput(filepath.Join(directory, "execute", "execution-abandonment.json"), true)
	if err != nil {
		return record, errors.New("retained_retire_record_unavailable")
	}
	var abandonment deployansible.ExecutionAbandonment
	if json.Unmarshal(saved, &abandonment) != nil || abandonment.Fence != fence {
		return record, errors.New("retained_retire_record_invalid")
	}
	return retainedRetiredExecution{
		Protocol:        retainedRetirementProtocol,
		StateDirectory:  directory,
		Generation:      fence.Generation,
		Operation:       fence.Operation,
		JobSHA256:       fence.JobSHA256,
		RequestSHA256:   fence.RequestSHA256,
		BundleSHA256:    fence.BundleSHA256,
		ReceiptSHA256:   abandonment.ReceiptSHA256,
		DispatchSHA256:  abandonment.DispatchSHA256,
		ConfigSHA256:    in.ConfigSHA256,
		ManifestSHA256:  in.ManifestSHA256,
		JournalSHA256:   in.JournalSHA256,
		BindingSHA256:   in.FenceEvidenceSHA256,
		BridgeMarkerSHA: markers["bridge"],
		ExitMarkerSHA:   markers["exit"],
		AttestedAt:      abandonment.AttestedAt,
	}, nil
}

// verifyRetainedFailedWorkspace accepts only a dispatched bridge-only attempt that
// failed without a completion proof, and only while its fence still describes it.
func verifyRetainedFailedWorkspace(
	directory, config, manifest, journal string,
) (retainedPrimaryRebuildInput, deployansible.ExecutionFence, error) {
	var in retainedPrimaryRebuildInput
	var fence deployansible.ExecutionFence
	raw, err := readRebuildInput(filepath.Join(directory, "prepared-input.json"), true)
	if err != nil {
		return in, fence, errors.New("retained_retire_prepared_unavailable")
	}
	if decodeRetainedReconcile(raw, &in) != nil || in.Directory != directory ||
		validateRetainedPrimaryRebuild(in) != nil {
		return in, fence, errors.New("retained_retire_prepared_invalid")
	}
	// The attempt claimed a retained exit with its own binding, so that marker has
	// to be retired as well; the lease list below is built from the same pair.
	if !in.BridgeOnly || in.RetainedExit == nil || in.RetainedExit.FenceSHA256 == in.FenceEvidenceSHA256 {
		return in, fence, errors.New("retained_retire_scope_not_bridge_only")
	}
	for _, original := range []struct {
		path, hash string
		private    bool
	}{
		{config, in.ConfigSHA256, true},
		{manifest, in.ManifestSHA256, false},
		{journal, in.JournalSHA256, true},
	} {
		value, readErr := readRebuildInput(original.path, original.private)
		if readErr != nil || digestSHA256(value) != original.hash {
			return in, fence, errors.New("retained_retire_original_changed")
		}
	}
	fence, err = inspectFailedGeneration(filepath.Join(directory, "execute"))
	if err != nil {
		return in, fence, err
	}
	return in, fence, nil
}

// inspectFailedGeneration returns the live fence of this workspace and refuses
// any workspace that carries completion, containment, drain or retry evidence,
// because those belong to the normal paths.
func inspectFailedGeneration(execute string) (deployansible.ExecutionFence, error) {
	var fence deployansible.ExecutionFence
	current, err := deployansible.InspectExecutionFence()
	if err != nil {
		return fence, errors.New("retained_retire_fence_unavailable")
	}
	if current == nil {
		return fence, errors.New("retained_retire_fence_required")
	}
	if filepath.Clean(current.JobDirectory) != execute {
		return fence, errors.New("retained_retire_fence_mismatch")
	}
	for _, pattern := range []string{
		"execution-completion.json",
		"execution-containment.json",
		"execution-drain-*.json",
		"retry-preparation-*.json",
	} {
		matches, globErr := filepath.Glob(filepath.Join(execute, pattern))
		if globErr != nil || len(matches) != 0 {
			return fence, errors.New("retained_retire_completion_evidence_present")
		}
	}
	claims, err := filepath.Glob(filepath.Join(execute, "execution-dispatch-*.json"))
	if err != nil || len(claims) != 1 ||
		filepath.Base(claims[0]) != "execution-dispatch-"+current.Generation+".json" {
		return fence, errors.New("retained_retire_dispatch_mismatch")
	}
	raw, err := readRebuildInput(filepath.Join(execute, "receipt.json"), true)
	if err != nil {
		return fence, errors.New("retained_retire_receipt_unavailable")
	}
	var saved struct {
		State      string `json:"state"`
		Generation string `json:"execution_generation"`
	}
	if json.Unmarshal(raw, &saved) != nil || saved.State != "failed" ||
		saved.Generation != current.Generation {
		return fence, errors.New("retained_retire_receipt_not_failed")
	}
	return *current, nil
}

// The exit is listed first so both admission locks are held before either host is
// observed; see the comment at the caller for what is retired and what is kept.
func openRetainedRetirementLeases(
	ctx context.Context,
	p *installplan.InstallPlan,
	in retainedPrimaryRebuildInput,
	generation string,
) ([]*retainedRetirementLease, error) {
	targets := []struct{ address, key, role, binding string }{
		{p.Exits[0].SSHHost, p.ExitSSHIdentity(p.Exits[0]), "exit", in.RetainedExit.FenceSHA256},
		{p.Bridge.SSHHost, p.BridgeSSHIdentity(), "bridge", in.FenceEvidenceSHA256},
	}
	leases := make([]*retainedRetirementLease, 0, len(targets))
	for _, target := range targets {
		l, err := openRetainedRetirementLease(
			ctx, p, target.address, target.key, target.role, target.binding, generation,
		)
		if err != nil {
			for _, opened := range leases {
				opened.close()
			}
			return nil, err
		}
		leases = append(leases, l)
	}
	return leases, nil
}

type retainedRetirementLease struct {
	cmd     *exec.Cmd
	input   io.WriteCloser
	scanner *bufio.Scanner
	role    string
}

func openRetainedRetirementLease(
	ctx context.Context,
	p *installplan.InstallPlan,
	address, key, role, binding, generation string,
) (*retainedRetirementLease, error) {
	args := retainedSSH(p, address, key, false, true, "mutate")
	args = append(args, strings.Join(quoteRetainedArgs([]string{
		"python3", "-u", "-c", retainedRetirementProgram, role, binding, generation,
	}), " "))
	c := exec.CommandContext(ctx, args[0], args[1:]...)
	input, err := c.StdinPipe()
	if err != nil {
		return nil, errors.New("retained_retire_lease_start_failed")
	}
	output, err := c.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, errors.New("retained_retire_lease_start_failed")
	}
	l := &retainedRetirementLease{cmd: c, input: input, scanner: bufio.NewScanner(output), role: role}
	if err = c.Start(); err != nil {
		_ = input.Close()
		return nil, errors.New("retained_retire_lease_start_failed")
	}
	if !l.scanner.Scan() || l.scanner.Text() != "verified" {
		l.close()
		return nil, errors.New("retained_retire_remote_preflight_failed")
	}
	return l, nil
}

func (l *retainedRetirementLease) close() { _ = l.input.Close(); _ = l.cmd.Wait() }

func (l *retainedRetirementLease) prove() error {
	if _, err := io.WriteString(l.input, "prove\n"); err != nil {
		return errors.New("retained_retire_unverified")
	}
	if !l.scanner.Scan() || l.scanner.Text() != "verified" {
		return errors.New("retained_retire_unverified")
	}
	return nil
}

func (l *retainedRetirementLease) abandon() (string, error) {
	if _, err := io.WriteString(l.input, "abandon\n"); err != nil {
		return "", errors.New("retained_retire_unverified")
	}
	if !l.scanner.Scan() || l.scanner.Text() != "abandoned" || !l.scanner.Scan() {
		return "", errors.New("retained_retire_unverified")
	}
	return l.proof()
}

// preserve re-proves the lease and reports the digest of the marker it left in
// place, so the receipt records evidence that was never mutated.
func (l *retainedRetirementLease) preserve() (string, error) {
	if _, err := io.WriteString(l.input, "preserve\n"); err != nil {
		return "", errors.New("retained_retire_unverified")
	}
	if !l.scanner.Scan() || l.scanner.Text() != "preserved" || !l.scanner.Scan() {
		return "", errors.New("retained_retire_unverified")
	}
	return l.proof()
}

func (l *retainedRetirementLease) proof() (string, error) {
	var proof struct {
		MarkerSHA256 string `json:"marker_sha256"`
	}
	if json.Unmarshal(l.scanner.Bytes(), &proof) != nil || !rebuildSHA.MatchString(proof.MarkerSHA256) {
		return "", errors.New("retained_retire_unverified")
	}
	return proof.MarkerSHA256, nil
}

// Both admission locks stay held across every proof and the whole mutation. EOF
// or a killed operator never means "retired", and no original byte is removed.
const retainedRetirementProgram = `import os,sys,stat,json,fcntl,subprocess,hashlib
from pathlib import Path
role,binding,generation=sys.argv[1],sys.argv[2],sys.argv[3]
state=Path('/var/lib/ultra-ansible')
system=Path('/etc/systemd/system')
dropin='[Unit]\nRefuseManualStart=yes\nConditionPathExists=/var/lib/ultra-ansible/retained-primary-admission-open\n'
units=['ultra-ansible-controller.service','ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']
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
  text=b' '.join(args).decode(errors='replace')
  assert not any(x in ['ultra-install','ansible-playbook','controller.py','reconcile.py','retained-primary-reconcile','rebuild-retained-primary'] for x in names)
  assert generation not in text
def prove():
 trusted(state,True)
 marker=trusted(state/'retained-primary-admission.json',private=True)
 raw=marker.read_bytes()
 assert json.loads(raw)=={'protocol':'retained-primary-admission-v1','binding_sha256':binding}
 assert not os.path.lexists(state/'retained-primary-admission-open')
 assert not os.path.lexists(state/'recovery-fence.json')
 assert not os.path.lexists(state/'recovery-anchor.json')
 for unit in units:
  p=trusted(system/(unit+'.d/90-retained-primary.conf'))
  assert p.read_text()==dropin
  properties=show(unit)
  assert properties.get('ActiveState') in ['inactive','failed']
  if properties.get('LoadState')=='loaded':assert properties.get('RefuseManualStart')=='yes'
 census()
 return raw
locks=[]
for path in [state/'infrastructure.lock',state/'operator-inputs/manual-deploy.lock']:
 trusted(path,private=True)
 fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(fd)
prove()
print('verified',flush=True)
def syncdir(p):
 fd=os.open(p,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
for line in sys.stdin:
 command=line.strip()
 if command=='prove':
  prove()
  print('verified',flush=True)
  continue
 if command=='preserve':
  raw=prove()
  print('preserved',flush=True)
  print(json.dumps({'role':role,'marker_sha256':hashlib.sha256(raw).hexdigest()}),flush=True)
  continue
 if command!='abandon':sys.exit(0)
 raw=prove()
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
 print(json.dumps({'role':role,'marker_sha256':digest}),flush=True)
 sys.stdin.buffer.read()
 break
`
