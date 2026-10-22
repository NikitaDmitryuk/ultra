package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	recoveryassets "github.com/NikitaDmitryuk/ultra/deploy/recovery"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// Only physical lookup roots move. Original prepared/request/seal bytes and
// their logical paths remain unchanged, so historical hashes stay verifiable.
func loadRecoveryPreparationRetainedEvidence(r recoveryPreparationRequest) (recoveryPreparationInputs, error) {
	var result recoveryPreparationInputs
	in, evidence, err := loadRetainedReconcileSnapshot(r.RetainedDirectory, r.ConfigPath, r.BaselineManifestPath,
		r.OriginalJournalPath, r.EvidenceSourceDirectory)
	if err != nil {
		return result, err
	}
	root := filepath.Dir(r.BaselineManifestPath)
	raw, err := readRebuildInput(filepath.Join(root, "release-manifest.json"), false)
	if err != nil || digestSHA256(raw) != in.ManifestSHA256 {
		return result, errors.New("recovery_preparation_original_baseline_incomplete")
	}
	baseline, err := verifyAutomationRelease(root, "")
	if err != nil || baseline.SchemaVersion != 1 || !hasAutomationCapability(baseline, "ansible-deploy-v1") {
		return result, errors.New("recovery_preparation_original_baseline_incomplete")
	}
	if _, _, err = retainedReconcileRelayIdentitySnapshot(in, r.BaselineManifestPath, r.BaselineSourceDirectory, r.RetainedDirectory); err != nil {
		return result, err
	}
	installers := map[string]string{}
	for _, architecture := range []string{"amd64", "arm64"} {
		asset, err := upgradeAsset(baseline, "ultra-install-linux-"+architecture)
		if err != nil {
			return result, errors.New("recovery_preparation_original_installers_missing")
		}
		installers[architecture] = asset.SHA
	}
	result = recoveryPreparationInputs{in, evidence, recoveryPreparationAdmission{
		Protocol: "ultra-recovery-preparation-admission-v1", FenceSHA256: evidence.Fence,
		BaselineManifestSHA256: in.ManifestSHA256, ConfigSHA256: in.ConfigSHA256, Phase: "sealed",
	}, installers}
	if !result.admission.valid() {
		return recoveryPreparationInputs{}, errors.New("recovery_preparation_binding_invalid")
	}
	return result, nil
}

func verifyRecoveryPreparationLegacyClosure(r recoveryPreparationRequest) error {
	fail := errors.New("recovery_preparation_legacy_closure_unverified")
	if !runtimeHostValidDigest(r.LegacyJournalSHA256) {
		return fail
	}
	root := filepath.Join("/var/lib/ultra-ansible/preflight-closures", r.LegacyJournalSHA256)
	raw, err := readRebuildInput(filepath.Join(root, "operation.json"), true)
	if err != nil || digestSHA256(raw) != r.LegacyJournalSHA256 {
		return fail
	}
	j, err := parseBridgePreflightJournal(raw)
	if err != nil {
		return fail
	}
	raw, err = readRebuildInput(filepath.Join(root, "receipt.json"), true)
	var receipt bridgePreflightReceipt
	if err != nil || decodeRetainedReconcile(raw, &receipt) != nil ||
		receipt.Protocol != "ultra-bridge-preflight-closure-v1" || receipt.Result != "preflight_failed_no_mutation" ||
		receipt.JournalSHA != r.LegacyJournalSHA256 || receipt.Commit != j.Commit || receipt.Version != j.Version ||
		receipt.Attempt != j.Attempt || receipt.ConfigSHA != j.StagedConfigSHA || receipt.ManifestSHA != j.ManifestSHA ||
		!receipt.Admission.valid() || receipt.Admission.FenceSHA256 != r.RetainedFenceSHA256 ||
		receipt.Admission.ConfigSHA256 != r.ConfigSHA256 || receipt.Admission.BaselineManifestSHA256 != r.BaselineManifestSHA256 {
		return fail
	}
	evidenceDirectory := filepath.Join(root, "evidence")
	entries, err := os.ReadDir(evidenceDirectory)
	if err != nil || len(entries) != 3 || operatorPrivate(evidenceDirectory, true) != nil {
		return fail
	}
	evidence := map[string]string{}
	for _, entry := range entries {
		raw, err = readForwardEvidence(filepath.Join(evidenceDirectory, entry.Name()))
		if err != nil {
			return fail
		}
		evidence[entry.Name()] = digestSHA256(raw)
	}
	raw, _ = json.Marshal(evidence)
	if digestSHA256(raw) != receipt.EvidenceSHA {
		return fail
	}
	return nil
}

// No operator SSH key or caller-provided DSN is needed on the bridge. The
// installed runtime's fixed dedicated-DB tunnel identifies the actual primary.
func verifyRecoveryPreparationPrimary(ctx context.Context, r recoveryPreparationRequest, in retainedPrimaryRebuildInput) error {
	p, err := installplan.LoadLifecycleConfig(r.ConfigPath)
	if err != nil || !localLifecycleMachineIdentity(p) || len(p.Exits) != 1 {
		return errors.New("recovery_preparation_local_bridge_required")
	}
	connection, err := recoveryassets.Scripts.ReadFile("db_connection.py")
	if err != nil {
		return err
	}
	program := string(connection) + recoveryPreparationPrimaryProgram
	command := exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", program, p.Database.Name,
		p.Exits[0].DialAddr, strconv.Itoa(p.Exits[0].Port), r.StateDirectory)
	raw, err := command.Output()
	if err != nil {
		return errors.New("recovery_preparation_primary_observation_failed")
	}
	var observed struct {
		Identity retainedPrimaryIdentity `json:"identity"`
		Primary  bool                    `json:"primary"`
		Routes   []exits.BootstrapEntry  `json:"routes"`
		Pending  int64                   `json:"pending"`
	}
	if decodeRetainedReconcile(raw, &observed) != nil || !observed.Primary || observed.Pending != 0 {
		return errors.New("recovery_preparation_primary_or_queue_changed")
	}
	route, err := validateRetainedRoute(p, observed.Routes)
	if err != nil {
		return err
	}
	raw, _ = json.Marshal(route)
	observed.Identity.RouteSHA256 = digestSHA256(raw)
	observed.Identity.MigrationsSHA256 = digestSHA256([]byte(observed.Identity.MigrationVersions))
	if observed.Identity != in.Primary {
		return errors.New("recovery_preparation_primary_identity_changed")
	}
	return nil
}

// Operator paths in historical evidence are never executed after relocation.
// Only the existing fleet identity and explicitly bound public SSH pins may be
// used for preparation; dedicated primary access stays on its installed tunnel.
func recoveryPreparationTransportPlan(
	r recoveryPreparationRequest,
	in recoveryPreparationInputs,
) (*installplan.InstallPlan, map[string]any, error) {
	p, err := installplan.LoadLifecycleConfig(r.ConfigPath)
	if err != nil || installplan.ValidatePlan(p) != nil || len(p.Exits) != 1 || !localLifecycleMachineIdentity(p) {
		return nil, nil, errors.New("recovery_preparation_local_bridge_required")
	}
	all, _ := in.retained.Inventory["all"].(map[string]any)
	children, _ := all["children"].(map[string]any)
	for _, expected := range []struct{ group, host, address string }{
		{"bridge", "bridge", p.Bridge.SSHHost}, {"exits", "exit_0", p.Exits[0].SSHHost},
		{"databases", "database", p.Database.PrimaryHost},
	} {
		group, _ := children[expected.group].(map[string]any)
		hosts, _ := group["hosts"].(map[string]any)
		host, _ := hosts[expected.host].(map[string]any)
		if host["ansible_host"] != expected.address {
			return nil, nil, errors.New("recovery_preparation_transport_target_changed")
		}
	}
	pins, err := readRebuildInput(r.KnownHostsPath, false)
	if err != nil || !runtimeHostValidDigest(r.KnownHostsSHA256) || digestSHA256(pins) != r.KnownHostsSHA256 {
		return nil, nil, errors.New("recovery_preparation_transport_pins_changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if exec.CommandContext(ctx, "/usr/bin/python3", "-I", "-c", recoveryPreparationFleetIdentityProgram).Run() != nil {
		return nil, nil, errors.New("recovery_preparation_original_fleet_identity_required")
	}
	p.SSH.User, p.SSH.Identity, p.SSH.StrictHostKey = "root", "/etc/ultra-fleet/id_ed25519", true
	p.Bridge.SSHIdentity = p.SSH.Identity
	p.Exits[0].SSHIdentity = p.SSH.Identity
	p.Automation.KnownHostsFile = r.KnownHostsPath
	p.BridgeNative = false
	local := true
	p.ControllerLocal, p.ControllerLocalTarget = &local, p.Bridge.SSHHost+"|"+p.Bridge.Address
	clone := *p
	clone.Database.Enabled = false
	inventory, err := bootstrapInventory(&clone, filepath.Join(r.StateDirectory, "transport"))
	return p, inventory, err
}

const recoveryPreparationFleetIdentityProgram = `import os,stat,pwd,subprocess
from pathlib import Path
root=Path('/etc/ultra-fleet')
for path in [root,*root.parents]:
 info=path.lstat()
 assert stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
allowed={0,pwd.getpwnam('ultra-relay').pw_uid}
for name,private in [('id_ed25519',True),('id_ed25519.pub',False)]:
 path=root/name;info=path.lstat()
 assert stat.S_ISREG(info.st_mode) and info.st_uid in allowed and info.st_nlink==1
 assert not info.st_mode&(0o077 if private else 0o022)
result=subprocess.run(['/usr/bin/ssh-keygen','-y','-P','','-f',str(root/'id_ed25519')],capture_output=True,text=True,timeout=5)
assert result.returncode==0
actual=result.stdout.strip().split()
expected=(root/'id_ed25519.pub').read_text().strip().split()
assert len(actual)>=2 and actual[0]=='ssh-ed25519' and len(expected)>=2 and expected[:2]==actual[:2]
`

const recoveryPreparationPrimaryProgram = `
import subprocess,sys
database,address,port,state=sys.argv[1:]
parsed=dsn_from_runtime(database)
query="""BEGIN READ ONLY;
SELECT json_build_object(
 'identity',json_build_object('system_identifier',(SELECT system_identifier::text FROM pg_control_system()),
   'database',current_database(),'database_oid',(SELECT oid::bigint FROM pg_database WHERE datname=current_database()),
   'migration_versions',(SELECT COALESCE(string_agg(version::text,',' ORDER BY version),'') FROM public.schema_migrations)),
 'primary',NOT pg_is_in_recovery(),
 'routes',(SELECT COALESCE(json_agg(json_build_object('name',name,'address',address,'port',port,
   'tunnel_uuid',tunnel_uuid,'pinned_peer_cert_sha256',pinned_peer_cert_sha256,'priority',priority,'enabled',enabled)), '[]'::json)
   FROM public.exit_nodes WHERE address=:'address' AND port=:port),
 'pending',(SELECT count(*) FROM public.cloud_operations WHERE state IN ('pending','unknown')
   OR body->>'state' IN ('pending','unknown') OR (body->>'state') IS DISTINCT FROM state));
ROLLBACK;
"""
with tempfile.TemporaryDirectory(prefix='primary-observation-',dir=state) as temporary:
 with pgpass(temporary,parsed) as environment:
  environment['PGOPTIONS']='-c default_transaction_read_only=on'
  result=subprocess.run(connection_args(parsed,database,'psql')+['--no-psqlrc','-qAt','-v','ON_ERROR_STOP=1',
    '-v','address='+address,'-v','port='+port],input=query,capture_output=True,text=True,timeout=30,env=environment)
  if result.returncode:raise ValueError('primary_observation_failed')
  observed=json.loads(result.stdout)
  print(json.dumps(observed))
`
