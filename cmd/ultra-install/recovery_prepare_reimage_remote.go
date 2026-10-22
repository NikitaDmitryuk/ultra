package main

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// Dynamic nodes have no retained-primary marker. They are independently bound
// by the unchanged DB registry, provider instance/IP and accepted SSH pin. This
// observer never creates locks, starts/stops services, or changes their relay.
func openBridgeReimageNode(
	ctx context.Context,
	p *installplan.InstallPlan,
	node bridgeReimageFleetRow,
) (*recoveryPreparationAdmissionLease, error) {
	args := retainedSSH(p, node.Address, p.SSH.Identity, false, true)
	args = append(
		args,
		strings.Join(quoteRetainedArgs([]string{"python3", "-u", "-c", bridgeReimageNodeRemote, node.Pin, strconv.Itoa(node.Port)}), " "),
	)
	return startRecoveryPreparationAdmission(exec.CommandContext(ctx, args[0], args[1:]...), "fleet-census")
}

func withBridgeReimageFleet(ctx context.Context, r recoveryPreparationRequest, in recoveryPreparationInputs, action func() error) error {
	if r.BridgeReimage == nil {
		return errors.New("bridge_reimage_proof_required")
	}
	p, _, err := recoveryPreparationTransportPlan(r, in)
	if err != nil {
		return err
	}
	nodes, err := verifyBridgeReimageProvider(ctx, p, r.BridgeReimage, in.retained)
	if err != nil {
		return err
	}
	leases := []*recoveryPreparationAdmissionLease{}
	defer func() {
		for _, l := range leases {
			l.close()
		}
	}()
	for _, node := range nodes {
		lease, e := openBridgeReimageNode(ctx, p, node)
		if e != nil {
			return e
		}
		leases = append(leases, lease)
	}
	if err = verifyRecoveryPreparationPrimary(ctx, r, in.retained); err != nil {
		return err
	}
	for _, l := range leases {
		if err = l.recheck(); err != nil {
			return err
		}
	}
	if err = verifyRecoveryPreparationPrimary(ctx, r, in.retained); err != nil {
		return err
	}
	return action()
}

const bridgeReimageNodeRemote = `import os,sys,stat,json,fcntl,subprocess,hashlib,ssl,socket,re
from pathlib import Path
pin,port=sys.argv[1:]
assert re.fullmatch('[a-f0-9]{64}',pin) and 0<int(port)<65536
state=Path('/var/lib/ultra-ansible');locks=[]
def trusted(path,directory=False):
 s=path.lstat();assert s.st_uid==0 and not s.st_mode&0o022
 assert stat.S_ISDIR(s.st_mode) if directory else stat.S_ISREG(s.st_mode) and s.st_nlink==1
 return path
if state.exists():
 trusted(state,True)
 for name in ['infrastructure.lock','operator/infrastructure.lock','operator-inputs/manual-deploy.lock']:
  path=state/name
  if os.path.lexists(path):
   trusted(path);fd=os.open(path,os.O_RDWR|os.O_NOFOLLOW);fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB);locks.append(fd)
def observe():
 for name in ['execution-fence.json','recovery-fence.json','recovery-anchor.json','lifecycle.json']:
  assert not os.path.lexists(state/name)
 for unit in ['ultra-ansible-controller.service','ultra-recovery-reconcile.service']:
  r=subprocess.run(['systemctl','show',unit,'--property=ActiveState','--property=MainPID'],capture_output=True,text=True,timeout=10)
  assert r.returncode in (0,1)
  props=dict(x.split('=',1) for x in r.stdout.splitlines() if '=' in x)
  assert props.get('ActiveState') in ('inactive','failed') and props.get('MainPID','0')=='0'
 for item in Path('/proc').iterdir():
  if not item.name.isdigit() or int(item.name)==os.getpid():continue
  try:args=(item/'cmdline').read_bytes().split(b'\0')
  except (FileNotFoundError,ProcessLookupError):continue
  names=[os.path.basename(x.decode(errors='replace')) for x in args]
  assert not any(x in ['ultra-install','ansible-playbook','controller.py','reconcile.py','ansible-controller','ansible-run','ansible-exit','operator-upgrade','deploy-operation','apply-remote'] or x.startswith('AnsiballZ_') for x in names)
 raw=trusted(Path('/etc/ultra-relay/spec.json')).read_bytes();spec=json.loads(raw)
 assert spec['role']=='exit' and spec['vless_port']==int(port)
 pem=trusted(Path('/etc/ultra-relay/fullchain.pem')).read_text()
 leaf=ssl.PEM_cert_to_DER_cert(pem[:pem.index('-----END CERTIFICATE-----')+25])
 assert hashlib.sha256(leaf).hexdigest()==pin
 context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);context.check_hostname=False;context.verify_mode=ssl.CERT_NONE
 with socket.create_connection(('127.0.0.1',int(port)),timeout=5) as connection:
  with context.wrap_socket(connection) as secured:assert secured.getpeercert(binary_form=True)==leaf
 return hashlib.sha256(raw).hexdigest()
original=observe();print('verified',flush=True)
for command in sys.stdin:
 assert command=='recheck\n' and observe()==original
 print('verified',flush=True)
`
