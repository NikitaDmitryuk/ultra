package main

// This command observes an existing successful execute. It never calls an
// Ansible runner, changes the database, retires a lifecycle, or removes a fence.
import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

type retainedReconcileEvidence struct {
	RetainedExit          *retainedBridgeExit     `json:"retained_exit,omitempty"`
	Protocol              string                  `json:"protocol"`
	Fence                 string                  `json:"fence_sha256"`
	Binding               string                  `json:"binding_sha256"`
	Artifacts             map[string]string       `json:"artifacts"`
	Primary               retainedPrimaryIdentity `json:"primary"`
	ConfigureCloudRuntime bool                    `json:"configure_cloud_runtime"`
	RelayBinarySHA256     string                  `json:"relay_binary_sha256,omitempty"`
	RelayUnitSHA256       string                  `json:"relay_unit_sha256,omitempty"`
}

func runRetainedReconcile(args []string, out io.Writer) error {
	if len(args) == 0 || (args[0] != "inspect" && args[0] != "activate-controller" &&
		args[0] != "retire-deleted-provider" && args[0] != "abandon-undispatched") {
		return errors.New("retained_reconcile_action_required")
	}
	activate := args[0] == "activate-controller"
	retire := args[0] == "retire-deleted-provider"
	abandon := args[0] == "abandon-undispatched"
	f := flag.NewFlagSet("retained-primary-reconcile", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	operatorStateDir := f.String("operator-state-dir", "", "local Ansible state root for nonroot operators")
	directory := f.String("state-dir", "", "existing successful recovery workspace")
	config := f.String("config", "", "original canonical config")
	manifest := f.String("manifest", "", "original release manifest")
	journal := f.String("original-journal", "", "original journal, never modified")
	receipt := f.String("receipt", "", "new private reconciliation evidence file")
	configureCloud := f.Bool("configure-cloud-runtime", false, "repair fixed bridge provider runtime after controller readiness")
	deletedProvider := f.String("provider-deletion-receipt", "", "verified exact provider deletion")
	fleet := f.String("fleet", "", "private complete pre-retirement fleet inventory")
	if f.Parse(args[1:]) != nil || f.NArg() != 0 {
		return errors.New("retained_reconcile_arguments_invalid")
	}
	if *configureCloud && !activate {
		return errors.New("retained_reconcile_cloud_requires_activation")
	}
	if retire != (*deletedProvider != "" && *fleet != "") || (!retire && (*deletedProvider != "" || *fleet != "")) {
		return errors.New("retained_reconcile_retirement_scope_required")
	}
	for _, p := range []string{*directory, *config, *manifest, *journal, *receipt} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return errors.New("retained_reconcile_absolute_paths_required")
		}
	}
	if err := configureOperatorExecutionState(*operatorStateDir); err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, cancelTimeout := context.WithTimeout(ctx, 3*time.Minute)
	defer cancelTimeout()
	lock, err := openOperatorLock(filepath.Join(filepath.Dir(*config), "."+filepath.Base(*config)+".manual-deploy.lock"), uint32(os.Geteuid()))
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	// An undispatched attempt has no successful execute, so it is proved and
	// retired on its own path rather than through the reconciliation snapshot.
	if abandon {
		return abandonRetainedUndispatchedAdmission(ctx, out, *directory, *config, *manifest, *journal, *receipt)
	}
	in, evidence, err := loadRetainedReconcile(*directory, *config, *manifest, *journal)
	if err != nil {
		return err
	}
	evidence.ConfigureCloudRuntime = *configureCloud
	if *configureCloud {
		evidence.RelayBinarySHA256, evidence.RelayUnitSHA256, err = retainedReconcileRelayIdentity(in, *manifest)
		if err != nil {
			return err
		}
	}
	p, err := installplan.LoadConfig(*config)
	if err != nil || p.Automation == nil || len(p.Exits) != 1 {
		return errors.New("retained_reconcile_config_invalid")
	}
	// Census runs before any SSH children and rejects independent local runners.
	if err = retainedLocalCensus(); err != nil {
		return err
	}
	raw, _ := json.Marshal(evidence)
	leases := []*retainedReconcileLease{}
	defer func() {
		for _, l := range leases {
			l.close()
		}
	}()
	for n, target := range []struct{ address, key string }{{p.Bridge.SSHHost, p.BridgeSSHIdentity()}, {p.Exits[0].SSHHost, p.ExitSSHIdentity(p.Exits[0])}} {
		role := "bridge"
		if n == 1 {
			role = "exit"
		}
		fence := evidence.Fence
		if role == "exit" && in.RetainedExit != nil {
			fence = in.RetainedExit.FenceSHA256
		}
		l, e := openRetainedReconcileLease(ctx, p, target.address, target.key, role, fence, raw, p.Exits[0].Port)
		if e != nil {
			return e
		}
		leases = append(leases, l)
	}
	if err = verifyRetainedReconcilePrimary(ctx, p, in); err != nil {
		return err
	}
	// Re-read every original byte while all admission locks remain held.
	_, again, err := loadRetainedReconcile(*directory, *config, *manifest, *journal)
	again.ConfigureCloudRuntime = *configureCloud
	if *configureCloud && err == nil {
		again.RelayBinarySHA256, again.RelayUnitSHA256, err = retainedReconcileRelayIdentity(in, *manifest)
	}
	if err != nil || !reflect.DeepEqual(again, evidence) {
		return errors.New("retained_reconcile_inputs_changed")
	}
	if retire {
		result, e := retireDeletedProvider(ctx, p, in, evidence, *deletedProvider, *fleet)
		if e != nil {
			return e
		}
		if e = publishRetainedReconcile(*receipt, result); e != nil {
			return e
		}
		_, e = fmt.Fprintln(
			out,
			"provider absence retirement verified; exact node and operation retained as history; scoped counts recorded",
		)
		return e
	}
	if err = publishRetainedReconcile(*receipt, raw); err != nil {
		return err
	}
	if activate {
		// Check DB again immediately before dispatch; controller remains fenced.
		if err = verifyRetainedReconcilePrimary(ctx, p, in); err != nil {
			return err
		}
		if err = leases[0].activate(); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(
		out,
		"retained-primary reconciliation verified; controller_activated=%t; evidence_sha256=%s\n",
		activate,
		digestSHA256(raw),
	)
	return err
}

func decodeRetainedReconcile(raw []byte, v any) error {
	if err := retainedReconcileUniqueJSON(raw); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("retained_reconcile_json_invalid")
	}
	return nil
}

// encoding/json otherwise silently accepts duplicate keys. Reject them before
// either typed decoding or semantic request comparison; keep numeric lexemes.
func retainedReconcileUniqueJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 128 {
			return errors.New("retained_reconcile_json_invalid")
		}
		t, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				k, ok := key.(string)
				if !ok || seen[k] {
					return errors.New("retained_reconcile_duplicate_json_key")
				}
				seen[k] = true
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err = value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("retained_reconcile_json_invalid")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("retained_reconcile_json_invalid")
	}
	return nil
}

func loadRetainedReconcile(directory, config, manifest, journal string) (retainedPrimaryRebuildInput, retainedReconcileEvidence, error) {
	return loadRetainedReconcileSnapshot(directory, config, manifest, journal, directory)
}

// The logical directory remains part of the authenticated historical request.
// Relocation changes only where its bytes are read, never their binding.
func loadRetainedReconcileSnapshot(
	directory, config, manifest, journal, logicalDirectory string,
) (retainedPrimaryRebuildInput, retainedReconcileEvidence, error) {
	var in retainedPrimaryRebuildInput
	e := retainedReconcileEvidence{Protocol: "ultra-retained-primary-reconcile-v1", Artifacts: map[string]string{}}
	read := func(name, path string, private bool) ([]byte, error) {
		raw, err := readRebuildInput(path, private)
		if err == nil {
			e.Artifacts[name] = digestSHA256(raw)
		}
		return raw, err
	}
	raw, err := read("prepared", filepath.Join(directory, "prepared-input.json"), true)
	if err != nil {
		return in, e, err
	}
	if err = decodeRetainedReconcile(raw, &in); err != nil {
		return in, e, err
	}
	physical := in
	physical.Directory = directory
	if !filepath.IsAbs(logicalDirectory) || filepath.Clean(logicalDirectory) != logicalDirectory ||
		in.Directory != logicalDirectory || validateRetainedPrimaryRebuild(physical) != nil {
		return in, e, errors.New("retained_reconcile_prepared_invalid")
	}
	for _, a := range []struct {
		name, path, hash string
		private          bool
	}{{"config", config, in.ConfigSHA256, true}, {"manifest", manifest, in.ManifestSHA256, false}, {"journal", journal, in.JournalSHA256, true}} {
		v, er := read(a.name, a.path, a.private)
		if er != nil || digestSHA256(v) != a.hash {
			return in, e, errors.New("retained_reconcile_original_changed")
		}
	}
	// Historical execute versions hashed the original compact prepared bytes,
	// preserving nested typed DNS field order. Current execute normalizes nested
	// maps first. Admit only these two serializers, never a caller-chosen digest.
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return in, e, errors.New("retained_reconcile_json_invalid")
	}
	historicalBinding := digestSHA256(compact.Bytes())
	normalized, _ := json.Marshal(in)
	normalizedBinding := digestSHA256(normalized)
	e.Fence = in.FenceEvidenceSHA256
	e.RetainedExit = in.RetainedExit
	e.Primary = in.Primary
	execute := filepath.Join(directory, "execute")
	request, err := read("request", filepath.Join(execute, "request.json"), true)
	if err != nil {
		return in, e, err
	}
	var submitted struct {
		ExecutionTimeoutSeconds *int64         `json:"execution_timeout_seconds,omitempty"`
		Inventory               map[string]any `json:"inventory"`
		Variables               map[string]any `json:"variables"`
	}
	if decodeRetainedReconcile(request, &submitted) != nil {
		return in, e, errors.New("retained_reconcile_request_changed")
	}
	if !retainedExecutionTimeoutMatches(in.ExecutionTimeoutSeconds, submitted.ExecutionTimeoutSeconds) {
		return in, e, errors.New("retained_reconcile_execution_timeout_changed")
	}
	binding, ok := submitted.Variables["ultra_retained_recovery_binding_sha256"].(string)
	if !ok || (binding != historicalBinding && binding != normalizedBinding) {
		return in, e, errors.New("retained_reconcile_binding_invalid")
	}
	e.Binding = binding
	vars := map[string]any{}
	for k, v := range in.Variables {
		vars[k] = v
	}
	vars["ultra_retained_primary"] = map[string]any{
		"system_identifier": in.Primary.SystemIdentifier,
		"database":          in.Primary.Database,
		"database_oid":      in.Primary.DatabaseOID,
		"migrations_sha256": in.Primary.MigrationsSHA256,
	}
	vars["ultra_retained_candidate_migration_versions"] = in.CandidateMigrationVersions
	vars["ultra_retained_recovery_binding_sha256"] = e.Binding
	vars["ultra_bootstrap_exit_host"] = "exit_0"
	vars["ultra_preserve_runtime"] = false
	wantRequest := map[string]any{"inventory": in.Inventory, "variables": vars}
	if submitted.ExecutionTimeoutSeconds != nil {
		wantRequest["execution_timeout_seconds"] = *submitted.ExecutionTimeoutSeconds
	}
	wantRaw, _ := json.Marshal(wantRequest)
	var want, actual any
	if decodeRetainedReconcile(wantRaw, &want) != nil || decodeRetainedReconcile(request, &actual) != nil ||
		!reflect.DeepEqual(actual, want) {
		return in, e, errors.New("retained_reconcile_request_changed")
	}
	var saved map[string]any
	for _, name := range []string{"job", "receipt"} {
		v, er := read(name, filepath.Join(execute, name+".json"), true)
		if er != nil {
			return in, e, er
		}
		saved = nil
		if retainedReconcileUniqueJSON(v) != nil || json.Unmarshal(v, &saved) != nil || saved["schema_version"] != float64(1) ||
			saved["operation"] != retainedRebuildOperation(in) ||
			saved["request_sha256"] != e.Artifacts["request"] ||
			saved["binary_sha256"] != e.Artifacts["request"] {
			return in, e, errors.New("retained_reconcile_execute_identity_invalid")
		}
		if name == "receipt" && saved["state"] != "succeeded" {
			return in, e, errors.New("retained_reconcile_execute_not_succeeded")
		}
	}
	result, err := read("result", filepath.Join(execute, "result.json"), true)
	if err != nil {
		return in, e, err
	}
	var values map[string]any
	if retainedReconcileUniqueJSON(result) != nil || json.Unmarshal(result, &values) != nil || !reflect.DeepEqual(saved["result"], values) {
		return in, e, errors.New("retained_reconcile_result_conflict")
	}
	for _, k := range []string{"verified", "retained_primary_verified", "relay_ready", "bot_ready", "main_exit_ready"} {
		if values[k] != true {
			return in, e, errors.New("retained_reconcile_health_not_verified")
		}
	}
	if values["recovery_binding_sha256"] != e.Binding {
		return in, e, errors.New("retained_reconcile_binding_invalid")
	}
	seal, err := read("bundle_receipt", filepath.Join(execute, "bundle.retention.json"), true)
	if err != nil {
		return in, e, err
	}
	if err = verifyRetainedReconcileBundleSnapshot(filepath.Join(execute, "bundle"), filepath.Join(logicalDirectory, "execute", "bundle"), seal, e.Artifacts["request"]); err != nil {
		return in, e, err
	}
	return in, e, nil
}

func verifyRetainedReconcileBundleSnapshot(root, logicalRoot string, raw []byte, request string) error {
	var seal struct {
		Schema    int               `json:"schema"`
		Path      string            `json:"path"`
		Identity  map[string]string `json:"identity"`
		Inventory map[string][]any  `json:"inventory"`
	}
	if retainedReconcileUniqueJSON(raw) != nil || json.Unmarshal(raw, &seal) != nil || seal.Schema != 1 || seal.Path != logicalRoot ||
		seal.Identity["request_sha256"] != request ||
		len(seal.Inventory) == 0 {
		return errors.New("retained_reconcile_bundle_seal_invalid")
	}
	seen := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		s, err := os.Lstat(path)
		if err != nil {
			return err
		}
		st, ok := s.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != uint32(os.Geteuid()) || s.Mode().Perm()&0022 != 0 ||
			s.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
			return errors.New("retained_reconcile_bundle_unsafe")
		}
		if path == root {
			if !s.IsDir() || s.Mode().Perm()&0077 != 0 {
				return errors.New("retained_reconcile_bundle_unsafe")
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		entry := seal.Inventory[filepath.ToSlash(rel)]
		seen++
		if s.IsDir() {
			if len(entry) != 2 || entry[0] != "directory" || entry[1] != float64(s.Mode().Perm()) {
				return errors.New("retained_reconcile_bundle_changed")
			}
			return nil
		}
		if !s.Mode().IsRegular() || st.Nlink != 1 {
			return errors.New("retained_reconcile_bundle_unsafe")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(entry) != 3 || entry[0] != "file" || entry[1] != digestSHA256(b) || entry[2] != float64(s.Mode().Perm()) {
			return errors.New("retained_reconcile_bundle_changed")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if seen != len(seal.Inventory) {
		return errors.New("retained_reconcile_bundle_incomplete")
	}
	return nil
}

func retainedLocalCensus() error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if _, er := strconv.Atoi(e.Name()); er != nil {
			continue
		}
		if e.Name() == fmt.Sprint(os.Getpid()) {
			continue
		}
		raw, er := os.ReadFile(filepath.Join("/proc", e.Name(), "cmdline"))
		if er != nil {
			if os.IsNotExist(er) || !e.IsDir() {
				continue
			}
			return errors.New("retained_reconcile_local_census_unavailable")
		}
		if retainedExecutorCommand(raw) {
			return errors.New("retained_reconcile_local_executor_present")
		}
	}
	return nil
}

func publishRetainedReconcile(path string, raw []byte) error {
	if rebuildNoSymlinkAncestors(filepath.Dir(path)) != nil {
		return errors.New("retained_reconcile_receipt_unsafe")
	}
	parent := filepath.Dir(path)
	s, err := os.Lstat(parent)
	if err != nil || !s.IsDir() || s.Mode().Perm() != 0700 {
		return errors.New("retained_reconcile_private_receipt_directory_required")
	}
	owner, ok := s.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		return errors.New("retained_reconcile_private_receipt_directory_required")
	}
	if _, statErr := os.Lstat(path); statErr == nil {
		old, err := readRebuildInput(path, true)
		if err != nil {
			return err
		}
		if bytes.Equal(old, raw) {
			return nil
		}
		return errors.New("retained_reconcile_receipt_conflict")
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	f, err := os.CreateTemp(parent, ".reconcile-")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Link(f.Name(), path); err != nil {
		return err
	}
	if err = os.Remove(f.Name()); err != nil {
		return err
	}
	d, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	return d.Sync()
}

func verifyRetainedReconcilePrimary(ctx context.Context, p *installplan.InstallPlan, in retainedPrimaryRebuildInput) error {
	id, err := observeRetainedPrimary(ctx, p, in)
	if err != nil || id != in.Primary {
		return errors.New("retained_reconcile_primary_changed")
	}
	key := p.Database.SSHIdentity
	if key == "" {
		key = p.SSH.Identity
	}
	query := `import subprocess,sys
r=subprocess.run(['runuser','-u','postgres','--','psql','--no-psqlrc','-qAt','-v','ON_ERROR_STOP=1','-d',sys.argv[1],'-c',"BEGIN READ ONLY; SELECT count(*) FROM public.cloud_operations WHERE state IN ('pending','unknown') OR body->>'state' IN ('pending','unknown') OR (body->>'state') IS DISTINCT FROM state; ROLLBACK;"],capture_output=True,text=True,timeout=20)
assert r.returncode==0 and r.stdout.strip()=='0'
print('verified')
`
	_, err = retainedRemote(ctx, p, p.Database.PrimaryHost, key, true, query, []string{p.Database.Name})
	if err != nil {
		return errors.New("retained_reconcile_cloud_queue_not_idle")
	}
	return nil
}

type retainedReconcileLease struct {
	cmd     *exec.Cmd
	input   io.WriteCloser
	scanner *bufio.Scanner
}

func openRetainedReconcileLease(
	ctx context.Context,
	p *installplan.InstallPlan,
	address, key, role, fence string,
	receipt []byte,
	port int,
) (*retainedReconcileLease, error) {
	botHost, err := retainedReconcileBotHost(p)
	if err != nil {
		return nil, err
	}
	args := retainedSSH(p, address, key, false, true, "mutate")
	args = append(
		args,
		strings.Join(
			quoteRetainedArgs(
				[]string{
					"python3",
					"-u",
					"-c",
					retainedReconcileRemote,
					role,
					fence,
					base64.StdEncoding.EncodeToString(receipt),
					fmt.Sprint(port),
					botHost,
					p.Features.MainExitDomain,
					p.Bridge.Address,
				},
			),
			" ",
		),
	)
	c := exec.CommandContext(ctx, args[0], args[1:]...)
	input, err := c.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := c.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return nil, err
	}
	l := &retainedReconcileLease{c, input, bufio.NewScanner(output)}
	if err = c.Start(); err != nil {
		_ = input.Close()
		return nil, errors.New("retained_reconcile_lease_start_failed")
	}
	if !l.scanner.Scan() || l.scanner.Text() != "verified" {
		l.close()
		return nil, errors.New("retained_reconcile_remote_preflight_failed")
	}
	return l, nil
}
func (l *retainedReconcileLease) close() { _ = l.input.Close(); _ = l.cmd.Wait() }
func (l *retainedReconcileLease) activate() error {
	if _, err := io.WriteString(l.input, "activate-controller\n"); err != nil {
		return err
	}
	if !l.scanner.Scan() || l.scanner.Text() != "activated" {
		return errors.New("retained_reconcile_activation_unverified")
	}
	return nil
}
