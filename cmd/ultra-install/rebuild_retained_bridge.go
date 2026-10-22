package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/google/uuid"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// Separate optional fields preserve the byte identity of historical two-host
// inputs. An exit fence is evidence of preservation, never a new admission.
type retainedBridgeExit struct {
	FenceSHA256       string `json:"fence_sha256"`
	SourceSHA256      string `json:"source_sha256"`
	SpecSHA256        string `json:"spec_sha256"`
	CertificateSHA256 string `json:"certificate_sha256"`
	TunnelUUID        string `json:"tunnel_uuid"`
}

func (e retainedBridgeExit) valid() bool {
	for _, h := range []string{e.FenceSHA256, e.SourceSHA256, e.SpecSHA256, e.CertificateSHA256} {
		if !rebuildSHA.MatchString(h) {
			return false
		}
	}
	return uuid.Validate(e.TunnelUUID) == nil
}

func (l *retainedReconcileLease) recheck() error {
	if _, err := io.WriteString(l.input, "recheck\n"); err != nil {
		return err
	}
	if !l.scanner.Scan() || l.scanner.Text() != "verified" {
		return errors.New("retained_bridge_exit_lease_lost")
	}
	return nil
}

func retainedRebuildOperation(in retainedPrimaryRebuildInput) string {
	if in.BridgeOnly {
		return retainedBridgeRebuildOperation
	}
	return retainedPrimaryRebuildOperation
}

func retainedMutationTargets(p *installplan.InstallPlan, bridgeOnly bool) []struct{ address, key string } {
	targets := []struct{ address, key string }{{p.Bridge.SSHHost, p.BridgeSSHIdentity()}}
	if !bridgeOnly {
		targets = append(targets, struct{ address, key string }{p.Exits[0].SSHHost, p.ExitSSHIdentity(p.Exits[0])})
	}
	return targets
}

func retainedFenceProgram(freshBridge bool) string {
	if !freshBridge {
		return retainedFenceLease
	}
	// Revalidate freshness under both admission locks, before claiming a marker.
	check := strings.ReplaceAll(retainedBridgeFreshCheck, "print('fresh')\n", "")
	return strings.Replace(retainedFenceLease, "marker=state/", check+"\nmarker=state/", 1)
}

func prepareRetainedBridgeController(p *installplan.InstallPlan, architecture, directory string, variables map[string]any) error {
	manifest, err := verifyAutomationRelease(p.Automation.ReleaseDir, p.Automation.Version)
	if err != nil {
		return err
	}
	for _, item := range []struct{ name, path, hash string }{
		{"ultra-install-linux-" + architecture, "ultra_install_source", "ultra_install_sha256"},
		{"ultra-ansible-runtime-linux-" + architecture + ".tar.gz", "ultra_controller_runtime_archive", "ultra_controller_runtime_sha256"},
	} {
		asset, e := upgradeAsset(manifest, item.name)
		if e != nil {
			return e
		}
		variables[item.path] = filepath.Join(p.Automation.ReleaseDir, asset.Name)
		variables[item.hash] = asset.SHA
	}
	variables["ultra_controller_directory"] = managedControllerDirectory(manifest.Version)
	variables["controller_stage_only"] = true
	variables["ultra_controller_bridge_address"] = p.Bridge.Address
	provider, err := prepareProviderSecrets(p, directory)
	if err != nil {
		return err
	}
	variables["ultra_retained_provider_key_source"] = provider
	return nil
}

func retainedInventoryHost(in retainedPrimaryRebuildInput, group, host string) map[string]any {
	all, _ := in.Inventory["all"].(map[string]any)
	groups, _ := all["children"].(map[string]any)
	g, _ := groups[group].(map[string]any)
	hosts, _ := g["hosts"].(map[string]any)
	h, _ := hosts[host].(map[string]any)
	return h
}

func loadRetainedBridgeSource(path string, p *installplan.InstallPlan) (retainedPrimaryRebuildInput, retainedReconcileEvidence, error) {
	var old retainedPrimaryRebuildInput
	var evidence retainedReconcileEvidence
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return old, evidence, errors.New("retained_bridge_source_required")
	}
	raw, err := readRebuildInput(path, true)
	var source recoveryInputSources
	if err != nil || decodeRetainedReconcile(raw, &source) != nil {
		return old, evidence, errors.New("retained_bridge_source_invalid")
	}
	// LegacyJournal belongs to a different protocol. It is neither consumed nor
	// retired here; the active operator journal remains unchanged.
	old, evidence, err = loadRetainedReconcile(source.RetainedDirectory, source.OriginalConfig,
		filepath.Join(source.BaselineRelease, "release-manifest.json"), source.OriginalJournal)
	if err != nil {
		return old, evidence, err
	}
	if old.BridgeOnly {
		return old, evidence, errors.New("retained_bridge_original_fleet_evidence_required")
	}
	if _, err = verifyAutomationRelease(source.BaselineRelease, ""); err != nil {
		return old, evidence, err
	}
	for _, target := range []struct{ group, host, address string }{
		{"bridge", "bridge", p.Bridge.SSHHost}, {"exits", "exit_0", p.Exits[0].SSHHost}, {"databases", "database", p.Database.PrimaryHost},
	} {
		if retainedInventoryHost(old, target.group, target.host)["ansible_host"] != target.address {
			return old, evidence, errors.New("retained_bridge_preserved_topology_changed")
		}
	}
	return old, evidence, nil
}

func observeRetainedBridgeExit(
	ctx context.Context,
	p *installplan.InstallPlan,
	old retainedPrimaryRebuildInput,
	e retainedReconcileEvidence,
) (*retainedBridgeExit, error) {
	spec, _ := retainedInventoryHost(old, "exits", "exit_0")["ultra_spec"].(map[string]any)
	tunnel, _ := spec["exit"].(map[string]any)
	uuid, _ := tunnel["tunnel_uuid"].(string)
	if uuid == "" {
		return nil, errors.New("retained_bridge_source_route_missing")
	}
	raw, err := retainedRemote(ctx, p, p.Exits[0].SSHHost, p.ExitSSHIdentity(p.Exits[0]), false, retainedBridgeExitObservation,
		[]string{uuid, fmt.Sprint(p.Exits[0].Port), p.Features.MainExitDomain})
	var exit retainedBridgeExit
	if err != nil || decodeRetainedReconcile(raw, &exit) != nil {
		return nil, errors.New("retained_bridge_exit_identity_unverified")
	}
	proof, _ := json.Marshal(e)
	exit.FenceSHA256 = e.Fence
	exit.SourceSHA256 = digestSHA256(proof)
	if !exit.valid() {
		return nil, errors.New("retained_bridge_exit_identity_invalid")
	}
	return &exit, nil
}

// Read only: checks the running TLS endpoint against its installed public leaf,
// and binds exact spec bytes and route UUID. No private key is read or emitted.
const retainedBridgeExitObservation = `import sys,os,stat,json,hashlib,socket,ssl
from pathlib import Path
uuid,port,hostname=sys.argv[1:]
def read(path):
 p=Path(path)
 for a in p.parents:
  s=a.lstat();assert stat.S_ISDIR(s.st_mode) and not s.st_mode&0o022
 s=p.lstat();assert stat.S_ISREG(s.st_mode) and s.st_nlink==1 and not s.st_mode&0o022
 return p.read_bytes()
raw=read('/etc/ultra-relay/spec.json');spec=json.loads(raw)
assert spec['role']=='exit' and spec['vless_port']==int(port) and spec['exit']['tunnel_uuid']==uuid
pem=read('/etc/ultra-relay/fullchain.pem').decode()
leaf=ssl.PEM_cert_to_DER_cert(pem[:pem.index('-----END CERTIFICATE-----')+25])
with socket.create_connection(('127.0.0.1',int(port)),timeout=5) as connection:
 with ssl.create_default_context().wrap_socket(connection,server_hostname=hostname) as secured:
  assert secured.getpeercert(binary_form=True)==leaf
print(json.dumps({'spec_sha256':hashlib.sha256(raw).hexdigest(),'certificate_sha256':hashlib.sha256(leaf).hexdigest(),'tunnel_uuid':uuid}))
`

const retainedBridgeFreshCheck = `import os,subprocess
for path in ['/etc/ultra-relay/spec.json','/etc/ultra-relay/environment','/etc/systemd/system/ultra-ansible-controller.service','/var/lib/ultra-ansible/retained-primary-admission.json']:
 assert not os.path.lexists(path)
for unit in ['ultra-relay.service','ultra-bot.service','ultra-ansible-controller.service']:
 r=subprocess.run(['systemctl','show',unit,'--property=LoadState','--property=ActiveState'],capture_output=True,text=True,timeout=10)
 assert r.returncode in [0,1]
 props=dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
 assert props.get('LoadState')=='not-found' and props.get('ActiveState')=='inactive'
print('fresh')
`
