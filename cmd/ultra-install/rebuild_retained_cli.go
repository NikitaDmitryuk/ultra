package main

import (
	"bufio"
	"bytes"
	"context"

	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
	"github.com/NikitaDmitryuk/ultra/internal/operatorssh"
)

// A standalone mutation must prove the local containment prerequisites before it
// creates a durable remote fence. Without this the run passes every CLI and SSH
// check, admits itself on the fleet, and only then fails inside the executor with
// no receipt: the empty stage/node/code triple observed in production.
var retainedLocalExecutionPreflight = deployansible.PreflightLocalExecution

// This is an explicit operator recovery, never a continuation or retirement of
// the lost predecessor journal. Its controller fence survives failure/reboot.
func runRetainedPrimaryCommand(args []string) error {
	fs := flag.NewFlagSet("rebuild-non-db execute", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	config := fs.String("config", "", "canonical operator config")
	manifestPath := fs.String("manifest", "", "verified local release manifest")
	journal := fs.String("original-journal", "", "retained original journal, read only")
	directory := fs.String("state-dir", "", "new private recovery workspace")
	operatorStateDir := fs.String("operator-state-dir", "", "local Ansible state root for nonroot operators")
	backup := fs.String("backup", "", "fresh age encrypted primary custom dump")
	backupMaxAge := fs.Duration("backup-max-age", 30*time.Minute, "maximum verified snapshot age")
	executionTimeout := fs.Duration("execution-timeout", 20*time.Minute, "maximum execution runtime")
	backupSHA := fs.String("backup-sha256", "", "expected encrypted backup digest")
	python := fs.String("python", "/usr/bin/python3", "controller Python")
	executable := fs.String("executable", "", "pinned operator Ansible executable")
	bridgeOnly := fs.Bool("bridge-only", false, "rebuild only the reimaged bridge; preserve the live permanent exit")
	authorizeFleet := fs.Bool(
		"authorize-new-fleet-key",
		false,
		"append the new bridge fleet public key on the retained exit, preserving existing keys",
	)
	retainedSource := fs.String("retained-source-spec", "", "private descriptor of successful retained fleet evidence")
	prepareOnly := fs.Bool("prepare-only", false, "validate and save private inputs without production mutation")
	acceptFleet := fs.Bool(
		"accept-reimaged-fleet",
		false,
		"operator attests former bridge/exit were reimaged and former dynamic exits removed",
	)
	dnsAttestation := fs.String(
		"dns-attestation",
		"",
		"private operator attestation of the DNS records the provider already holds",
	)
	if fs.Parse(args) != nil || fs.NArg() != 0 || (*bridgeOnly == *acceptFleet) || (*bridgeOnly != (*retainedSource != "")) ||
		(*bridgeOnly != *authorizeFleet) {
		return errors.New("retained_primary_explicit_operator_scope_required")
	}
	if *backupMaxAge <= 0 || *executionTimeout <= 0 || *executionTimeout%time.Second != 0 {
		return errors.New("retained_primary_duration_invalid")
	}
	for _, p := range []string{*config, *manifestPath, *journal, *directory, *backup, *python, *executable} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return errors.New("retained_primary_absolute_paths_required")
		}
	}
	// The attestation is optional; when the operator names one it must already
	// be an absolute canonical path, exactly like every other private input.
	if *dnsAttestation != "" && (!filepath.IsAbs(*dnsAttestation) || filepath.Clean(*dnsAttestation) != *dnsAttestation) {
		return errors.New("retained_primary_absolute_paths_required")
	}
	if err := configureOperatorExecutionState(*operatorStateDir); err != nil {
		return err
	}
	// Prove this process can dispatch before anything is read, created or fenced.
	// A failed run must not leave a workspace that blocks the retry, and it must
	// never reach the fleet: the durable admission is one shot.
	if err := retainedLocalExecutionPreflight(); err != nil {
		return fmt.Errorf("retained_primary_local_execution_preflight_failed: %w", err)
	}
	configRaw, err := readRebuildInput(*config, true)
	if err != nil {
		return err
	}
	journalRaw, err := readRebuildInput(*journal, true)
	if err != nil {
		return err
	}
	manifestRaw, err := readRebuildInput(*manifestPath, false)
	if err != nil {
		return err
	}
	if !json.Valid(journalRaw) {
		return errors.New("retained_primary_journal_invalid")
	}
	p, err := installplan.LoadConfig(*config)
	if err != nil {
		return errors.New("retained_primary_config_invalid")
	}
	if p.SSH.User != "root" || (p.Database.Enabled && p.Database.SSHUser != "" && p.Database.SSHUser != "root") {
		return errors.New("operator_root_transport_required")
	}
	if p.Automation == nil || p.Automation.Ingress == nil || p.Automation.Ingress.ForwardHost != "" || !p.Database.Enabled ||
		len(p.Exits) != 1 ||
		p.AdoptRuntime ||
		p.Bridge.ReuseSpec {
		return errors.New("retained_primary_scope_requires_one_fresh_bridge_exit_and_separate_database")
	}
	var prior retainedPrimaryRebuildInput
	var priorEvidence retainedReconcileEvidence
	if *bridgeOnly {
		prior, priorEvidence, err = loadRetainedBridgeSource(*retainedSource, p)
		if err != nil {
			return err
		}
	}
	credentialDSN, err := retainedExistingDatabaseCredentials(p)
	if err != nil {
		return err
	}
	// Only application artifacts are selected from this immutable candidate. The
	// operator recovery executor/playbook are independently compiled local code.
	p.Automation.ReleaseDir = filepath.Dir(*manifestPath)
	manifest, err := verifyAutomationRelease(p.Automation.ReleaseDir, p.Automation.Version)
	if err != nil {
		return errors.New("retained_primary_release_unverified")
	}
	if manifest.DatabaseSchemaMax < 1 || manifest.DatabaseSchemaMax > 10000 {
		return errors.New("retained_primary_schema_contract_invalid")
	}
	versions := make([]string, manifest.DatabaseSchemaMax)
	for n := range versions {
		versions[n] = strconv.Itoa(n + 1)
	}
	migrationVersions := strings.Join(versions, ",")
	if err = retainedRuntimePreflight(*python, *executable); err != nil {
		return err
	}
	backupMetadata, err := verifyRetainedBackupBundle(
		*backup,
		*backupSHA,
		p.SourceValues["ULTRA_OPERATOR_AGE_IDENTITY_FILE"],
		retainedSourceSHA256(p.Database.PrimaryHost, p.Database.Name),
		p.Database.Name,
		*backupMaxAge,
		time.Now(),
	)
	if err != nil {
		return err
	}
	uid := uint32(os.Geteuid())
	lock, err := openOperatorLock(filepath.Join(filepath.Dir(*config), "."+filepath.Base(*config)+".manual-deploy.lock"), uid)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	workspace, err := openRetainedWorkspace(*directory, uid)
	if err != nil {
		return err
	}
	defer func() { _ = workspace.Close() }()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	ctx, err = deployansible.WithExecutionTimeout(ctx, *executionTimeout)
	if err != nil {
		return err
	}
	inventory, err := bootstrapInventory(p, *directory)
	if err != nil {
		return err
	}
	all := inventory["all"].(map[string]any)
	common := all["vars"].(map[string]any)
	children := all["children"].(map[string]any)
	host := func(group, name string) map[string]any {
		return children[group].(map[string]any)["hosts"].(map[string]any)[name].(map[string]any)
	}
	// The retained DB accepts operator SSH only through bridge. This proxy never
	// copies private operator keys onto either application host.
	host("databases", "database")["ansible_ssh_common_args"] = common["ansible_ssh_common_args"].(string) + " -o " + shellQuote(
		"ProxyCommand="+retainedProxyCommand(p),
	)
	// Architecture is independently observed with pinned SSH before rendering.
	inspection := map[string]bootstrapInspection{}
	for _, entry := range []struct{ alias, address, key string }{{"bridge", p.Bridge.SSHHost, p.BridgeSSHIdentity()}, {"exit_0", p.Exits[0].SSHHost, p.ExitSSHIdentity(p.Exits[0])}} {
		raw, e := retainedRemote(
			ctx,
			p,
			entry.address,
			entry.key,
			false,
			"import platform; print({'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine(),''))",
			nil,
		)
		arch := strings.TrimSpace(string(raw))
		if e != nil {
			return e
		}
		if arch != "amd64" && arch != "arm64" {
			return fmt.Errorf("retained_primary_architecture_unparsable: role=%s response=%q", entry.alias, raw[:min(len(raw), 200)])
		}
		inspection[entry.alias] = bootstrapInspection{Architecture: arch}
	}
	retainedRoute, err := observeRetainedRoute(ctx, p)
	if err != nil {
		return err
	}
	if p.Exits[0].TunnelUUID != "" && p.Exits[0].TunnelUUID != retainedRoute.TunnelUUID {
		return errors.New("retained_primary_configured_route_identity_mismatch")
	}
	desired, err := installplan.RenderDesiredStateWithOptions(
		p,
		installplan.RenderOptions{PriorBootstrap: []exits.BootstrapEntry{retainedRoute}},
	)
	if err != nil {
		return errors.New("retained_primary_render_failed")
	}
	if desired.DBDSN != credentialDSN {
		return errors.New("retained_primary_credentials_changed")
	}
	// No provisioning/replication/import declaration ever enters this request.
	desired.PostgresConfig = nil
	if err = prepareBootstrapVariables(p, desired, inventory, inspection, *directory); err != nil {
		return err
	}
	// Component-specific result destinations are overridden by the single runner.
	delete(host("exits", "exit_0"), "ultra_result_file")
	variables := map[string]any{}
	for _, key := range []string{"ultra_db_tunnel_private_key_source", "ultra_db_tunnel_private_key_sha256"} {
		variables[key] = common[key]
	}
	ingressRaw, _ := json.Marshal(p.Automation.Ingress)
	var ingress map[string]any
	if json.Unmarshal(ingressRaw, &ingress) != nil {
		return errors.New("retained_primary_ingress_invalid")
	}
	variables["ultra_ingress"] = ingress
	variables["ultra_ingress_email"] = p.Automation.Ingress.Email
	variables["ultra_ingress_domains"] = uniqueIngressDomains(p.Automation.Ingress.Domain, p.Bot.Domain, p.PublicSubscriptionDomain())
	variables["ultra_ingress_transaction"] = "/var/lib/ultra-ingress/retained-" + digestSHA256([]byte(*directory))
	variables["ultra_bot_domain"] = p.Bot.Domain
	variables["ultra_bot_port"] = p.Bot.Port
	variables["ultra_subscription_domain"] = p.PublicSubscriptionDomain()
	variables["ultra_subscription_enabled"] = true
	variables["ultra_bridge_ipv4"] = p.Bridge.Address
	if err = prepareAnsibleDNSAttested(p, variables, *config, *dnsAttestation, nil); err != nil {
		return err
	}
	if *bridgeOnly {
		if err = prepareRetainedBridgeController(p, inspection["bridge"].Architecture, *directory, variables); err != nil {
			return err
		}
	}
	raw, _ := json.Marshal(inventory)
	var normalized map[string]any
	if json.Unmarshal(raw, &normalized) != nil {
		return errors.New("retained_primary_inventory_invalid")
	}
	in := retainedPrimaryRebuildInput{
		Inventory:                  normalized,
		Variables:                  variables,
		JournalSHA256:              digestSHA256(journalRaw),
		ConfigSHA256:               digestSHA256(configRaw),
		ManifestSHA256:             digestSHA256(manifestRaw),
		CandidateMigrationVersions: migrationVersions,
		CandidateMigrationsSHA256:  digestSHA256([]byte(migrationVersions)),
		BackupSnapshotUTC:          backupMetadata.SnapshotStarted.UTC().Format(time.RFC3339),
		BackupSHA256:               *backupSHA,
		BackupMaxAgeSeconds:        backupMaxAge.Seconds(),
		ExecutionTimeoutSeconds:    int64(*executionTimeout / time.Second),
		Directory:                  *directory,
		Python:                     *python,
		Executable:                 *executable,
	}
	primary, err := observeRetainedPrimary(ctx, p, in)
	if err != nil {
		return err
	}
	in.Primary = primary
	if *bridgeOnly {
		if primary != prior.Primary {
			return errors.New("retained_bridge_primary_or_route_changed")
		}
		in.BridgeOnly = true
		in.RetainedExit, err = observeRetainedBridgeExit(ctx, p, prior, priorEvidence)
		if err != nil {
			return err
		}
		if in.RetainedExit.TunnelUUID != retainedRoute.TunnelUUID {
			return errors.New("retained_bridge_route_identity_changed")
		}
	}
	if primary.MigrationVersions != migrationVersions {
		return errors.New("retained_primary_candidate_migrations_mismatch")
	}
	// Bind operator scope and fresh authenticated backup to a durable fence; this
	// is not fabricated predecessor/collector evidence and does not retire it.
	fenceBinding := digestSHA256([]byte(in.JournalSHA256 + in.ConfigSHA256 + in.ManifestSHA256 + uuid.NewString()))
	in.FenceEvidenceSHA256 = fenceBinding
	if err = validateRetainedPrimaryRebuild(in); err != nil {
		return err
	}
	prepared, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(*directory, "prepared-input.json"), prepared, 0600); err != nil {
		return err
	}
	var exitLease *retainedReconcileLease
	if *bridgeOnly {
		if err = retainedLocalCensus(); err != nil {
			return err
		}
		priorEvidence.RetainedExit = in.RetainedExit
		raw, _ := json.Marshal(priorEvidence)
		lease, e := openRetainedReconcileLease(
			ctx,
			p,
			p.Exits[0].SSHHost,
			p.ExitSSHIdentity(p.Exits[0]),
			"exit",
			priorEvidence.Fence,
			raw,
			p.Exits[0].Port,
		)
		if e != nil {
			return e
		}
		exitLease = lease
		defer lease.close()
	}
	if *bridgeOnly {
		if _, e := retainedRemote(ctx, p, p.Bridge.SSHHost, p.BridgeSSHIdentity(), false, retainedBridgeFreshCheck, nil); e != nil {
			return fmt.Errorf("retained_bridge_fresh_machine_required: %w", e)
		}
	}
	if *prepareOnly {
		if err = recordRetainedBackupAdmission(*directory, backupMetadata, *backupMaxAge, time.Now()); err != nil {
			return err
		}
		fmt.Println("retained-primary inputs validated; production unchanged")
		return nil
	}
	if err = revalidateRetainedBackupFreshness(backupMetadata, *backupMaxAge, time.Now()); err != nil {
		return err
	}
	// Check both hosts before either receives mutations. A local terminal receipt
	// cannot establish that orphaned executors drained after a runner crash.
	for _, entry := range retainedMutationTargets(p, *bridgeOnly) {
		if _, e := retainedRemote(ctx, p, entry.address, entry.key, false, retainedFenceAdmissionCheck, nil); e != nil {
			return fmt.Errorf("retained_primary_existing_admission_requires_manual_reconciliation: %w", e)
		}
	}
	if err = recordRetainedBackupAdmission(*directory, backupMetadata, *backupMaxAge, time.Now()); err != nil {
		return err
	}
	for _, entry := range retainedMutationTargets(p, *bridgeOnly) {
		release, e := holdRetainedFence(ctx, p, entry.address, entry.key, fenceBinding, *bridgeOnly)
		if e != nil {
			return e
		}
		defer release()
	}
	deps := retainedPrimaryRebuildDependencies{
		VerifyFence: func(ctx context.Context, _ retainedPrimaryRebuildInput) error {
			for _, entry := range retainedMutationTargets(p, *bridgeOnly) {
				if _, e := retainedRemote(ctx, p, entry.address, entry.key, false, retainedFenceVerify, []string{fenceBinding}); e != nil {
					return fmt.Errorf("retained_primary_fence_unverified: %w", e)
				}
			}
			if in.BridgeOnly {
				if e := exitLease.recheck(); e != nil {
					return e
				}
				if _, e := retainedRemote(ctx, p, p.Exits[0].SSHHost, p.ExitSSHIdentity(p.Exits[0]), false, retainedFenceVerify, []string{in.RetainedExit.FenceSHA256}); e != nil {
					return e
				}
				observed, e := observeRetainedBridgeExit(ctx, p, prior, priorEvidence)
				// The source proof is unchanged; the live hashes must match exactly.
				if e != nil || observed.SpecSHA256 != in.RetainedExit.SpecSHA256 ||
					observed.CertificateSHA256 != in.RetainedExit.CertificateSHA256 ||
					observed.TunnelUUID != in.RetainedExit.TunnelUUID {
					return errors.New("retained_bridge_exit_changed")
				}
			}
			return nil
		},
		ObservePrimary: func(ctx context.Context, in retainedPrimaryRebuildInput) (retainedPrimaryIdentity, error) {
			return observeRetainedPrimary(ctx, p, in)
		},
	}
	if err = runRetainedPrimaryRebuild(ctx, in, deps); err != nil {
		return err
	}
	fmt.Println("retained-primary recovery verified; controller admission fence retained; original journal unchanged")
	return nil
}

func quoteRetainedArgs(args []string) []string {
	out := make([]string, len(args))
	for n, a := range args {
		out[n] = shellQuote(a)
	}
	return out
}
func retainedSSH(p *installplan.InstallPlan, address, key string, proxy, destination bool, profiles ...string) []string {
	profile := "probe"
	if len(profiles) > 0 && profiles[0] == "mutate" {
		profile = "mutate"
	}
	args := []string{
		"ssh", "-F", "/dev/null", "-T",
		"-o", "BatchMode=yes",
		"-o", "IdentitiesOnly=yes",
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-o", "GlobalKnownHostsFile=/dev/null",
	}
	args = append(args, operatorssh.DefaultPolicy.Options(profile)...)
	args = append(args, "-o", "UserKnownHostsFile="+p.Automation.KnownHostsFile, "-i", key)
	if proxy {
		args = append(args, "-o", "ProxyCommand="+retainedProxyCommand(p, profile))
	}
	if destination {
		args = append(args, "root@"+address)
	}
	return args
}
func retainedProxyCommand(p *installplan.InstallPlan, profiles ...string) string {
	profile := "probe"
	if len(profiles) > 0 && profiles[0] == "mutate" {
		profile = "mutate"
	}
	jump := retainedSSH(p, p.Bridge.SSHHost, p.BridgeSSHIdentity(), false, false, profile)
	jump = append(jump, "-W", "%h:%p", "root@"+p.Bridge.SSHHost)
	return strings.Join(quoteRetainedArgs(jump), " ")
}

func retainedRemote(
	ctx context.Context,
	p *installplan.InstallPlan,
	address, key string,
	proxy bool,
	program string,
	parameters []string,
) ([]byte, error) {
	return retainedRemoteOperation(ctx, p, address, key, proxy, program, parameters, false)
}

func retainedMutation(
	ctx context.Context,
	p *installplan.InstallPlan,
	address, key string,
	proxy bool,
	program string,
	parameters []string,
) ([]byte, error) {
	return retainedRemoteOperation(ctx, p, address, key, proxy, program, parameters, true)
}

func retainedRemoteOperation(
	ctx context.Context,
	p *installplan.InstallPlan,
	address, key string,
	proxy bool,
	program string,
	parameters []string,
	mutate bool,
) ([]byte, error) {
	profile := "probe"
	if mutate {
		profile = "mutate"
	}
	args := retainedSSH(p, address, key, proxy, true, profile)
	remote := append([]string{"python3", "-"}, parameters...)
	args = append(args, strings.Join(quoteRetainedArgs(remote), " "))
	role := "exit"
	if proxy {
		role = "database"
	} else if address == p.Bridge.SSHHost {
		role = "bridge"
	}
	run := runRetainedReadOnlySSH
	if mutate {
		run = runRetainedMutationSSH
	}
	out, err := run(ctx, role, args, []byte(program), func(line string) { fmt.Fprintln(os.Stderr, line) })
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("retained_primary_remote_cancelled: %w", ctx.Err())
		}
		if retainedReadOnlyFailureKind(err) == "transport_exhausted" {
			return nil, fmt.Errorf("retained_primary_remote_transport_failed: role=%s: %w", role, err)
		}
		return nil, fmt.Errorf("retained_primary_remote_check_failed: role=%s: %w", role, err)
	}
	return out, nil
}

func observeRetainedPrimary(
	ctx context.Context,
	p *installplan.InstallPlan,
	_ retainedPrimaryRebuildInput,
) (retainedPrimaryIdentity, error) {
	program := `import subprocess,json,sys,hashlib
q="BEGIN READ ONLY; SELECT json_build_object('system_identifier',(SELECT system_identifier::text FROM pg_control_system()),'database',current_database(),'database_oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),'primary',NOT pg_is_in_recovery(),'migration_versions',COALESCE(string_agg(version::text,',' ORDER BY version),'')) FROM public.schema_migrations; ROLLBACK;"
r=subprocess.run(['runuser','-u','postgres','--','psql','--no-psqlrc','-At','-v','ON_ERROR_STOP=1','-d',sys.argv[1],'-c',q],capture_output=True,text=True,timeout=20)
if r.returncode:sys.exit(1)
j=json.loads(next(x for x in r.stdout.splitlines() if x.startswith('{')))
if not j.pop('primary'):sys.exit(1)
j['migrations_sha256']=hashlib.sha256(j['migration_versions'].encode()).hexdigest()
print(json.dumps(j))
`
	key := p.Database.SSHIdentity
	if key == "" {
		key = p.SSH.Identity
	}
	raw, err := retainedRemote(ctx, p, p.Database.PrimaryHost, key, true, program, []string{p.Database.Name})
	var id retainedPrimaryIdentity
	if err != nil {
		return id, err
	}
	if json.Unmarshal(raw, &id) != nil {
		return id, errors.New("retained_primary_observation_failed")
	}
	route, err := observeRetainedRoute(ctx, p)
	if err != nil {
		return id, err
	}
	routeRaw, _ := json.Marshal(route)
	id.RouteSHA256 = digestSHA256(routeRaw)
	return id, nil
}
func observeRetainedRoute(ctx context.Context, p *installplan.InstallPlan) (exits.BootstrapEntry, error) {
	program := `import subprocess,json,sys,os
q="BEGIN READ ONLY; SELECT COALESCE(json_agg(json_build_object('name',name,'address',address,'port',port,'tunnel_uuid',tunnel_uuid,'pinned_peer_cert_sha256',pinned_peer_cert_sha256,'priority',priority,'enabled',enabled)), '[]'::json) FROM public.exit_nodes WHERE address=:'address' AND port=:port; ROLLBACK;"
r=subprocess.run(['runuser','-u','postgres','--','psql','--no-psqlrc','-qAt','-v','ON_ERROR_STOP=1','-v','address='+sys.argv[2],'-v','port='+sys.argv[3],'-d',sys.argv[1]],input=q,capture_output=True,text=True,timeout=20,env=dict(os.environ,PGOPTIONS='-c default_transaction_read_only=on'))
if r.returncode:sys.exit(1)
print(r.stdout)
`
	key := p.Database.SSHIdentity
	if key == "" {
		key = p.SSH.Identity
	}
	raw, err := retainedRemote(
		ctx,
		p,
		p.Database.PrimaryHost,
		key,
		true,
		program,
		[]string{p.Database.Name, p.Exits[0].DialAddr, strconv.Itoa(p.Exits[0].Port)},
	)
	var rows []exits.BootstrapEntry
	if err != nil {
		return exits.BootstrapEntry{}, err
	}
	if json.Unmarshal(bytes.TrimSpace(raw), &rows) != nil {
		return exits.BootstrapEntry{}, errors.New("retained_primary_exact_existing_route_required")
	}
	return validateRetainedRoute(p, rows)
}
func validateRetainedRoute(p *installplan.InstallPlan, rows []exits.BootstrapEntry) (exits.BootstrapEntry, error) {
	if len(rows) != 1 {
		return exits.BootstrapEntry{}, errors.New("retained_primary_exact_existing_route_required")
	}
	route := rows[0]
	if route.Address != p.Exits[0].DialAddr || route.Port != p.Exits[0].Port || route.Enabled == nil || !*route.Enabled ||
		uuid.Validate(route.TunnelUUID) != nil {
		return route, errors.New("retained_primary_existing_route_invalid")
	}
	// A reimaged pinned exit cannot regain its old certificate without escrow.
	// This recovery supports the existing CA route only; no primary pin is reset.
	if p.Features.MainExitDomain == "" || route.PinnedPeerCertSHA256 != "" {
		return route, errors.New("retained_primary_existing_route_certificate_escrow_required")
	}
	return route, nil
}
func retainedExistingDatabaseCredentials(p *installplan.InstallPlan) (string, error) {
	path := p.Secrets.DatabaseCredentialsFile
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("retained_primary_existing_database_credentials_required")
	}
	if _, err := readRebuildInput(path, true); err != nil {
		return "", errors.New("retained_primary_existing_database_credentials_invalid")
	}
	dsn, err := installplan.ReadDatabaseCredentials(path)
	if err != nil {
		return "", errors.New("retained_primary_existing_database_credentials_invalid")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme != "postgres" || u.User == nil || u.Hostname() != "127.0.0.1" || u.Port() != "25432" ||
		strings.TrimPrefix(u.Path, "/") != p.Database.Name ||
		u.User.Username() != p.Database.User {
		return "", errors.New("retained_primary_existing_database_credentials_identity_mismatch")
	}
	if password, ok := u.User.Password(); !ok || password == "" {
		return "", errors.New("retained_primary_existing_database_credentials_required")
	}
	return dsn, nil
}

const retainedFenceDropin = "[Unit]\nRefuseManualStart=yes\nConditionPathExists=/var/lib/ultra-ansible/retained-primary-admission-open\n"

const retainedFenceAdmissionCheck = `import os
assert not os.path.lexists('/var/lib/ultra-ansible/retained-primary-admission.json'), 'retained_primary_existing_admission_requires_manual_reconciliation'
print('unclaimed')
`

// The process retains both admission locks until the operator runner exits. The
// root-owned systemd conditions persist after crash/reboot. No journal is changed.
const retainedFenceLease = `import os,sys,stat,fcntl,subprocess,json
from pathlib import Path
binding=sys.argv[1]
def need(x):
 if not x:raise RuntimeError('fence_invalid')
def directory(p,mode):
 p=Path(p);p.mkdir(mode=mode,parents=True,exist_ok=True);s=p.lstat();need(stat.S_ISDIR(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022);return p
state=directory('/var/lib/ultra-ansible',0o700)
locks=[]
for p in [state/'infrastructure.lock',directory(state/'operator-inputs',0o700)/'manual-deploy.lock']:
 fd=os.open(p,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);s=os.fstat(fd);need(stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(fd)
marker=state/'retained-primary-admission.json'
raw=json.dumps({'protocol':'retained-primary-admission-v1','binding_sha256':binding},sort_keys=True).encode()
# One shot, including same binding and claimed successful terminal receipts.
# O_EXCL closes the preflight/acquisition race; locks alone cannot prove drain.
fd=os.open(marker,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600)
os.write(fd,raw);os.fsync(fd);os.close(fd)
fd=os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
need(not (state/'retained-primary-admission-open').exists())
content='[Unit]\nRefuseManualStart=yes\nConditionPathExists=/var/lib/ultra-ansible/retained-primary-admission-open\n'
for unit in ['ultra-ansible-controller.service','ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']:
 folder=directory('/etc/systemd/system/'+unit+'.d',0o755);p=folder/'90-retained-primary.conf'
 if p.exists():need(p.read_text()==content)
 else:
  fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644);os.write(fd,content.encode());os.fsync(fd);os.close(fd)
for folder in [state, state/'operator-inputs',Path('/etc/systemd/system')]+[Path('/etc/systemd/system/'+unit+'.d') for unit in ['ultra-ansible-controller.service','ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']]:
 fd=os.open(folder,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW);os.fsync(fd);os.close(fd)
subprocess.run(['systemctl','daemon-reload'],check=True)
for unit in ['ultra-ansible-controller.service','ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']:
 r=subprocess.run(['systemctl','show',unit,'--value','--property=LoadState'],capture_output=True,text=True)
 if r.stdout.strip()=='loaded':subprocess.run(['systemctl','disable','--now',unit],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print('ready',flush=True)
sys.stdin.buffer.read()
`
const retainedFenceVerify = `import os,sys,stat,json,subprocess
from pathlib import Path
s=Path('/var/lib/ultra-ansible');p=s/'retained-primary-admission.json';i=p.lstat()
assert stat.S_ISREG(i.st_mode) and i.st_uid==0 and stat.S_IMODE(i.st_mode)==0o600 and i.st_nlink==1
assert json.loads(p.read_text())=={'protocol':'retained-primary-admission-v1','binding_sha256':sys.argv[1]}
assert not (s/'retained-primary-admission-open').exists()
for unit in ['ultra-ansible-controller.service','ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']:
 p=Path('/etc/systemd/system/'+unit+'.d/90-retained-primary.conf');i=p.lstat()
 assert stat.S_ISREG(i.st_mode) and i.st_uid==0 and not i.st_mode&0o022 and i.st_nlink==1
 assert p.read_text()=='[Unit]\nRefuseManualStart=yes\nConditionPathExists=/var/lib/ultra-ansible/retained-primary-admission-open\n'
 r=subprocess.run(['systemctl','show',unit,'--property=ActiveState','--property=RefuseManualStart','--property=LoadState'],capture_output=True,text=True)
 assert r.returncode in [0,1]
 v=dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
 assert v.get('ActiveState') in ['inactive','failed']
 if v.get('LoadState')=='loaded':assert v.get('RefuseManualStart')=='yes'
for proc in Path('/proc').iterdir():
 if not proc.name.isdigit() or int(proc.name)==os.getpid():continue
 try:
  args=(proc/'cmdline').read_bytes().split(b'\0')
  names=[os.path.basename(x.decode(errors='replace')) for x in args]
  assert not any(x in ['ultra-install','ansible-playbook','controller.py'] for x in names)
 except (FileNotFoundError,ProcessLookupError):pass
print('verified')
`

func holdRetainedFence(ctx context.Context, p *installplan.InstallPlan, address, key, binding string, freshBridge bool) (func(), error) {
	args := retainedSSH(p, address, key, false, true, "mutate")
	program := retainedFenceProgram(freshBridge)
	args = append(args, strings.Join(quoteRetainedArgs([]string{"python3", "-u", "-c", program, binding}), " "))
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err = cmd.Start(); err != nil {
		return nil, errors.New("retained_primary_fence_start_failed")
	}
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() || scanner.Text() != "ready" {
		_ = input.Close()
		_ = cmd.Wait()
		return nil, errors.New("retained_primary_durable_fence_failed")
	}
	return func() { _ = input.Close(); _ = cmd.Wait() }, nil
}
