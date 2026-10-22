#!/usr/bin/python
"""Operation-bound behavioral proof for preserving the broker retirement floor.

Probes run the exact broker bytes with an isolated socket/state and no jobs.
The production ledger is only read, including during rollback verification.
"""
import array
import io
import tarfile
import configparser
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import subprocess
import tempfile
import time
import uuid

ROOT = Path('/var/lib/ultra-ansible')
UNIT = Path('/etc/systemd/system/ultra-ansible-controller.service')
CURRENT = Path('/opt/ultra-ansible/current')
SHA = re.compile(r'[a-f0-9]{64}')
DIRECTORY = re.compile(r'/opt/ultra-ansible/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}')


def need(ok):
    if not ok:
        raise ValueError('controller_enforcement_unverified')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path, private=False, limit=256 * 1024 * 1024):
    path = Path(path)
    need(not any(item.is_symlink() for item in (path, *path.parents)))
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
         and not info.st_mode & (0o077 if private else 0o022)
         and info.st_nlink == 1 and info.st_size <= limit)
    return path.read_bytes()


def canonical_id(value):
    return isinstance(value, str) and str(uuid.UUID(value)) == value


def snapshot(root):
    raw = regular(root / 'lifecycle-retired.json', True, 65536)
    ledger = json.loads(raw)
    need(set(ledger) == {'version', 'ids'} and type(ledger['version']) is int
         and ledger['version'] == 1 and isinstance(ledger['ids'], list)
         and all(canonical_id(item) for item in ledger['ids'])
         and len(ledger['ids']) == len(set(ledger['ids'])))
    lifecycle_raw = regular(root / 'lifecycle.json', True, 4096)
    lifecycle = json.loads(lifecycle_raw)
    need(set(lifecycle) == {'id', 'phase'} and canonical_id(lifecycle['id'])
         and lifecycle['phase'] in ('released', 'applying', 'checking')
         and lifecycle['id'] not in ledger['ids'])
    return raw, ledger, lifecycle_raw, lifecycle


def tree_contents(directory):
    """Bind the rollback Python/runtime tree as well as its archive marker."""
    result = {}
    for base, dirs, files in os.walk(directory, followlinks=False):
        need(len(result) + len(dirs) + len(files) <= 30000)
        for name in sorted(dirs + files):
            path = Path(base) / name
            info = path.lstat()
            need(info.st_uid == os.geteuid() and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o022))
            if name == '__pycache__' and stat.S_ISDIR(info.st_mode):
                continue
            if path.parent.name == '__pycache__' and stat.S_ISREG(info.st_mode):
                match = re.fullmatch(r'(.+)\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc', name)
                source = path.parent.parent / (match.group(1) + '.py') if match else None
                if source and source.is_file() and not source.is_symlink():
                    continue
            relative = str(path.relative_to(directory))
            if stat.S_ISLNK(info.st_mode):
                result[relative] = ['link', os.readlink(path)]
            elif stat.S_ISREG(info.st_mode):
                result[relative] = ['file', digest(regular(path)), stat.S_IMODE(info.st_mode)]
            else:
                need(stat.S_ISDIR(info.st_mode))
                result[relative] = ['directory', stat.S_IMODE(info.st_mode)]
    return result


def tree_digest(directory):
    return digest(json.dumps(tree_contents(directory), sort_keys=True, separators=(',', ':')).encode())


def sealed_candidate(candidate):
    """The common controller role seals all installed members before selection."""
    directory = Path(candidate['directory'])
    receipt = ROOT / 'retention' / (digest(str(directory).encode()) + '.json')
    sealed = json.loads(regular(receipt, True, 4 * 1024 * 1024))
    need(set(sealed) == {'schema', 'path', 'identity', 'inventory'} and sealed['schema'] == 1
         and sealed['path'] == str(directory) and sealed['identity'] == {
             'ultra-install': candidate['installer_sha256'],
             'runtime.sha256': digest((candidate['runtime_sha256'] + '\n').encode())}
         and sealed['inventory'] == tree_contents(directory))


def identity(directory, unit_raw):
    need(isinstance(directory, str) and DIRECTORY.fullmatch(directory))
    root = Path(directory)
    need(root.is_dir() and not root.is_symlink() and root.stat().st_uid == os.geteuid()
         and not root.stat().st_mode & 0o077)
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(unit_raw.decode())
    service = parser['Service']
    expected = [str(root / 'ultra-install'), 'ansible-controller', '--executable',
                str(root / 'venv/bin/ansible-playbook')]
    need(shlex.split(service['ExecStart']) == expected and service['User'] == 'root'
         and service['Group'] == 'root' and service['KillMode'] == 'control-group'
         and not service.get('ExecStartPre') and not service.get('ExecStartPost'))
    runtime = regular(root / 'runtime.sha256', True, 128).decode().strip()
    need(SHA.fullmatch(runtime))
    return {'directory': directory, 'installer_sha256': digest(regular(root / 'ultra-install')),
            'runtime_sha256': runtime, 'unit_sha256': digest(unit_raw),
            'tree_sha256': tree_digest(root), 'unit': unit_raw.decode()}


def recovery_admission(request, request_sha):
    expected = {'protocol':'ultra-recovery-preparation-admission-v1', 'phase':'sealed',
                'fence_sha256':request['retained_fence_sha256'],
                'baseline_manifest_sha256':request['baseline_manifest_sha256'],
                'config_sha256':request['config_sha256']}
    if request.get('bridge_reimage') is not None:
        # The Go origin sealer already authenticated the successful new restore
        # and preserved exit. Consume its request-bound terminal proof rather
        # than guessing that both hosts have the new bridge's fence.
        terminal = json.loads(regular(Path(request['state_directory']) / 'origins_sealed.json', True, 1048576))
        need(terminal.get('protocol') == 'ultra-recovery-preparation-phase-v1'
             and terminal.get('request_sha256') == request_sha and terminal.get('phase') == 'origins_sealed'
             and terminal.get('verified') is True)
        admission = terminal.get('evidence', {}).get('admission', {})
        need(isinstance(admission, dict) and set(admission) == set(expected) | {'exit_fence_sha256','bridge_genesis'}
             and all(admission.get(key) == value for key,value in expected.items())
             and SHA.fullmatch(admission.get('exit_fence_sha256', ''))
             and SHA.fullmatch(admission.get('bridge_genesis', '')))
        need(json.loads(regular(ROOT / 'bridge-reimage-genesis.json', True, 4096)) ==
             {'protocol':'ultra-bridge-reimage-genesis-v1','binding_sha256':admission['bridge_genesis']})
        expected = admission
    return expected


def recovery_context(request_sha, operation, candidate, manifest, read_only=False):
    if not request_sha:
        return None
    need(SHA.fullmatch(request_sha) and canonical_id(operation))
    operations = ROOT / 'deploy-operations'
    current = json.loads(regular(operations / 'current.json', True, 4096))
    need(current.get('schema') == 1 and SHA.fullmatch(current.get('request_sha256', '')))
    operation_root = operations / current['request_sha256']
    raw = regular(operation_root / 'request.json', True, 1048576)
    need(digest(raw) == current['request_sha256'])
    envelope = json.loads(raw)
    state = json.loads(regular(operation_root / 'state.json', True, 4096))
    need(envelope.get('schema') == 2 and state.get('state') in (('running','blocked','submitted','prepared','retry_prepared') if read_only else ('running',))
         and state.get('request_sha256') == current['request_sha256'])
    cgroup = Path('/proc/self/cgroup').read_text().splitlines()
    need(read_only or any(line.endswith(':/system.slice/ultra-deploy-' + current['request_sha256'] + '.service') for line in cgroup))
    request = envelope['preparation']
    raw = regular(Path(request['state_directory']) / 'request.json', True, 1048576)
    need(digest(raw) == request_sha and json.loads(raw) == request
         and request['protocol'] == 'ultra-recovery-preparation-request-v1'
         and request['tools_manifest_sha256'] == manifest)
    admission = recovery_admission(request, request_sha)
    need(json.loads(regular(ROOT / 'recovery-preparation-admission.json', True, 4096)) == admission
         and json.loads(regular(ROOT / 'retained-primary-admission.json', True, 4096)) ==
         {'protocol':'retained-primary-admission-v1','binding_sha256':admission['fence_sha256']}
         and not os.path.lexists(ROOT / 'retained-primary-admission-open'))
    if not prepared_schedules_restored(request, request_sha):
        for name in ['ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']:
            need(regular(UNIT.parent / (name + '.d') / '90-retained-primary.conf', limit=4096).decode() == recovery_blocked())
    baseline_raw = regular(Path(request['baseline_manifest_path']), limit=1048576)
    need(digest(baseline_raw) == admission['baseline_manifest_sha256'])
    baseline = json.loads(baseline_raw)
    assets = {item['name']:item['sha256'] for item in baseline['assets']}
    context = {'request_sha256':request_sha,'operation_id':operation,'candidate':candidate,'assets':assets}
    recovery_dropin(context)
    return context


def recovery_blocked():
    return '[Unit]\nRefuseManualStart=yes\nConditionPathExists=/var/lib/ultra-ansible/retained-primary-admission-open\n'


def recovery_authorization(context):
    return {'protocol':'ultra-recovery-controller-handoff-v1','request_sha256':context['request_sha256'],
            'operation_id':context['operation_id'],'candidate':context['candidate']}


def recovery_dropin(context):
    path = UNIT.parent / 'ultra-ansible-controller.service.d/90-retained-primary.conf'
    content = regular(path, limit=4096).decode()
    if content == recovery_blocked():
        return False
    auth = ROOT / ('recovery-controller-' + context['request_sha256'] + '.json')
    expected = '[Unit]\nRefuseManualStart=no\nConditionPathExists=' + str(auth) + '\n'
    need(content == expected and json.loads(regular(auth, True, 4096)) == recovery_authorization(context))
    return True


def stopped_identity(context):
    # This is an artifact identity observation, never executor quiescence proof.
    # The separately authenticated sealed origins established dispatch closure.
    need(context is not None and CURRENT.is_symlink())
    output = subprocess.run(['systemctl','show','--property=ActiveState,MainPID,ControlPID,FragmentPath,RefuseManualStart',
                             'ultra-ansible-controller.service'],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                            timeout=5,check=True).stdout.decode()
    values = dict(line.split('=',1) for line in output.splitlines())
    opened = recovery_dropin(context)
    need(values['ActiveState'] in ('inactive','failed') and values['MainPID'] == values['ControlPID'] == '0'
         and values['FragmentPath'] == str(UNIT) and values['RefuseManualStart'] == ('no' if opened else 'yes'))
    directory = os.readlink(CURRENT)
    observed = identity(directory, regular(UNIT, limit=65536))
    candidate = context['candidate']
    if directory == candidate['directory']:
        need(opened and all(observed[k] == candidate[k] for k in ('installer_sha256','runtime_sha256','unit_sha256')))
        sealed_candidate(candidate)
    else:
        need(not opened)
        architecture = candidate['architecture']
        need(observed['installer_sha256'] == context['assets']['ultra-install-linux-' + architecture]
             and observed['runtime_sha256'] == context['assets']['ultra-ansible-runtime-linux-' + architecture + '.tar.gz'])
    return observed


def running_identity(recovery=None):
    output = subprocess.run(['systemctl', 'show', '--property=ActiveState,MainPID,FragmentPath,DropInPaths,ControlGroup',
                             'ultra-ansible-controller.service'], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=5, check=True).stdout.decode()
    values = dict(line.split('=', 1) for line in output.splitlines())
    need(values['ActiveState'] == 'active' and values['FragmentPath'] == str(UNIT)
         and (values['DropInPaths'] == '' or (recovery is not None and recovery_dropin(recovery) and values['DropInPaths'] == str(UNIT.parent / 'ultra-ansible-controller.service.d/90-retained-primary.conf'))) and values['ControlGroup'] == '/system.slice/ultra-ansible-controller.service'
         and values['MainPID'].isdigit() and int(values['MainPID']) > 1)
    proc = Path('/proc') / values['MainPID']
    need(proc.stat().st_uid == os.geteuid()
         and (proc / 'cgroup').read_bytes() == b'0::/system.slice/ultra-ansible-controller.service\n')
    executable = os.readlink(proc / 'exe')
    directory = str(Path(executable).parent)
    need(DIRECTORY.fullmatch(directory) and executable == directory + '/ultra-install')
    need((proc / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0') ==
         [os.fsencode(directory + '/ultra-install'), b'ansible-controller', b'--executable',
          os.fsencode(directory + '/venv/bin/ansible-playbook')])
    return directory, digest((proc / 'exe').read_bytes())


def live_identity(recovery=None, allow_stopped=False):
    need(CURRENT.is_symlink())
    directory = os.readlink(CURRENT)
    result = identity(directory, regular(UNIT, limit=65536))
    try:
        need(running_identity(recovery) == (directory, result['installer_sha256']))
    except ValueError:
        need(allow_stopped and recovery is not None)
        need(stopped_identity(recovery) == result)
    return result


def intent_raw(proof):
    return json.dumps(proof, sort_keys=True, separators=(',', ':')).encode()


def intent_paths(proof):
    stem = 'controller-enforcement-' + proof['operation_id']
    return ROOT / (stem + '.json'), ROOT / ('.' + stem + '.pending')


def intent_file(path, proof):
    # Only this protocol's exact sibling pair may temporarily have two links.
    need(not any(item.is_symlink() for item in (path, *path.parents)))
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
         and not info.st_mode & 0o077 and info.st_size <= 1048576
         and path.read_bytes() == intent_raw(proof))
    return info


def intent_present(proof):
    path, pending = intent_paths(proof)
    final_exists, pending_exists = os.path.lexists(path), os.path.lexists(pending)
    if not final_exists:
        if pending_exists:
            need(intent_file(pending, proof).st_nlink == 1)
        return False
    final = intent_file(path, proof)
    if pending_exists:
        temporary = intent_file(pending, proof)
        need(final.st_nlink == temporary.st_nlink == 2
             and (final.st_dev, final.st_ino) == (temporary.st_dev, temporary.st_ino))
    else:
        need(final.st_nlink == 1)
    return True


def save_intent(proof):
    """Publish once; recover only the authenticated interrupted sibling link."""
    path, pending = intent_paths(proof)
    published = intent_present(proof)
    if not published and not os.path.lexists(pending):
        descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(intent_raw(proof))
            stream.flush()
            os.fsync(stream.fileno())
    if not published:
        # Authenticate a surviving fully written pending file before linking.
        need(intent_file(pending, proof).st_nlink == 1)
        os.link(pending, path)
    # A process interruption after link leaves an exact, recoverable pair.
    need(intent_present(proof))
    if os.path.lexists(pending):
        os.unlink(pending)
    directory = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def transition_identity(proof, recovery=None):
    """Retry only the recorded old/new unit, symlink and process combinations."""
    need(intent_present(proof) and CURRENT.is_symlink())
    old, new = proof['rollback'], proof['candidate']
    selected = os.readlink(CURRENT)
    unit_sha = digest(regular(UNIT, limit=65536))
    try:
        running = running_identity(recovery)
    except ValueError:
        observed = stopped_identity(recovery)
        running = (observed['directory'], observed['installer_sha256'])
    need(selected in (old['directory'], new['directory'])
         and unit_sha in (old['unit_sha256'], new['unit_sha256'])
         and running in ((old['directory'], old['installer_sha256']),
                         (new['directory'], new['installer_sha256'])))
    if selected == new['directory'] or unit_sha == new['unit_sha256'] or running[0] == new['directory']:
        sealed_candidate(new)


def exchange(path, action, operation='', fd=None):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect(str(path))
        data = json.dumps({'action': action, 'id': operation}).encode() + b'\n'
        ancillary = [] if fd is None else [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))]
        client.sendmsg([data], ancillary)
        raw, control, flags, _ = client.recvmsg(65536, socket.CMSG_SPACE(12))
        descriptors = []
        for level, kind, value in control:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                items = array.array('i')
                items.frombytes(value[:len(value) - len(value) % items.itemsize])
                descriptors.extend(items)
        try:
            need(not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC))
            while b'\n' not in raw:
                chunk = client.recv(65536 - len(raw))
                need(chunk and len(raw) < 65536)
                raw += chunk
            return json.loads(raw), descriptors
        except BaseException:
            for descriptor in descriptors:
                os.close(descriptor)
            raise


def probe(executable, ledger):
    """Exercise real broker startup, retirement and retained-OFD restart."""
    with tempfile.TemporaryDirectory(prefix='ultra-enforcement-') as temporary:
        root = Path(temporary)
        state = root / 'state'
        state.mkdir(mode=0o700)
        active, retired = str(uuid.uuid4()), str(uuid.uuid4())
        isolated = {'version': 1, 'ids': ledger['ids'] + [retired]}
        isolated_raw = json.dumps(isolated, sort_keys=True).encode()
        for name, raw in [('lifecycle-retired.json', isolated_raw),
                          ('lifecycle.json', json.dumps({'id': active, 'phase': 'released'}).encode())]:
            (state / name).write_bytes(raw)
            (state / name).chmod(0o600)
        path = root / 'socket'
        process = None
        held = []

        def start():
            child = subprocess.Popen([str(executable), 'ansible-controller', '--state', str(state),
                                      '--socket', str(path), '--python', '/usr/bin/python3',
                                      '--executable', '/usr/bin/true', '--allowed-user', 'root'],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, close_fds=True)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                need(child.poll() is None)
                if path.exists():
                    return child
                time.sleep(0.02)
            child.kill()
            child.wait()
            raise ValueError('controller_enforcement_probe_timeout')

        def request(action, operation='', fd=None):
            response, descriptors = exchange(path, action, operation, fd)
            held.extend(descriptors)
            return response, descriptors

        try:
            process = start()
            for action in ('lease-applying', 'lease-resume', 'lease-checking', 'lease-release', 'lease-attach'):
                response, descriptors = request(action, retired)
                need(response.get('code') == 'lifecycle_retired' and not descriptors)
            response, descriptors = request('lease-applying', active)
            need(response.get('state') == 'applying' and not response.get('code') and not descriptors)
            response, descriptors = request('lease-attach', active)
            need(response.get('state') == 'applying' and not response.get('code') and len(descriptors) == 1)
            retained = descriptors[0]
            need(request('ready')[0].get('code') == 'lifecycle_busy')
            need(request('submit', str(uuid.uuid4()))[0].get('code') == 'lifecycle_busy')
            process.terminate()
            process.wait(timeout=5)
            process = None
            path.unlink(missing_ok=True)
            process = start()
            need(request('ready')[0].get('code') == 'lifecycle_busy')
            response, descriptors = request('lease-resume', active, retained)
            need(response.get('state') == 'applying' and not response.get('code') and not descriptors)
            need(request('lease-applying', retired)[0].get('code') == 'lifecycle_retired')
            need((state / 'lifecycle-retired.json').read_bytes() == isolated_raw)
        finally:
            for descriptor in held:
                os.close(descriptor)
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def validate_candidate(candidate):
    need(set(candidate) == {'directory', 'installer_sha256', 'runtime_sha256', 'unit_sha256', 'architecture'})
    need(DIRECTORY.fullmatch(candidate['directory']) and candidate['architecture'] in ('amd64', 'arm64')
         and all(SHA.fullmatch(candidate[key]) for key in ('installer_sha256', 'runtime_sha256', 'unit_sha256')))


def machine_sha():
    return digest(regular('/etc/machine-id', limit=128).strip())


def verify(proof, operation, scope, manifest, candidate, phase='reserved', root=None):
    root = ROOT if root is None else root
    validate_candidate(candidate)
    need(isinstance(proof, dict) and set(proof) == {'schema', 'operation_id', 'scope_sha256', 'manifest_sha256',
         'machine_sha256', 'ledger_sha256', 'source_lifecycle', 'candidate', 'rollback'})
    need(type(proof['schema']) is int and proof['schema'] == 1 and proof['operation_id'] == operation and proof['scope_sha256'] == scope
         and proof['manifest_sha256'] == manifest and proof['candidate'] == candidate
         and proof['machine_sha256'] == machine_sha())
    raw, _, _, lifecycle = snapshot(root)
    need(digest(raw) == proof['ledger_sha256'])
    source = proof['source_lifecycle']
    need(set(source) == {'id', 'phase'} and source['phase'] == 'released' and canonical_id(source['id']))
    if phase == 'completion':
        need(lifecycle['id'] == operation)
    elif phase == 'preflight':
        need(lifecycle == source or lifecycle['id'] == operation)
    else:
        need(lifecycle['id'] == operation and lifecycle['phase'] in ('applying', 'checking'))
    rollback = proof['rollback']
    need(identity(rollback['directory'], rollback['unit'].encode()) == rollback)
    return lifecycle


def observe_recovery_proof(p):
    # This entrypoint has no publication/start/selection path. It is used by
    # external reconciliation after a lost supervisor, never by module.execute.
    proof=p['proof'];candidate=p['candidate']
    phase='reserved' if p.get('require_candidate') else 'preflight'
    lifecycle=verify(proof,p['operation_id'],p['scope_sha256'],p['manifest_sha256'],candidate,phase)
    path=UNIT.parent/'ultra-ansible-controller.service.d/90-retained-primary.conf'
    context = recovery_context(p['recovery_request_sha256'],p['operation_id'],candidate,p['manifest_sha256'],read_only=True) if os.path.lexists(path) else None
    observed=live_identity(context,context is not None and not p.get('require_candidate'))
    selected=all(observed[k]==candidate[k] for k in ('directory','installer_sha256','runtime_sha256','unit_sha256'))
    need(selected or observed==proof['rollback'])
    if lifecycle==proof['source_lifecycle']:
        need(observed==proof['rollback'])
    if p.get('require_candidate'):
        need(selected);sealed_candidate(candidate)
    return {'verified':True,'lifecycle':lifecycle}


def open_recovery_controller(p, context):
    need(context is not None and p['proof'] and intent_present(p['proof']))
    lifecycle = verify(p['proof'],p['operation_id'],p['scope_sha256'],p['manifest_sha256'],p['candidate'],'before')
    need(lifecycle == {'id':p['operation_id'],'phase':'applying'} and CURRENT.is_symlink()
         and os.readlink(CURRENT) == p['candidate']['directory'])
    observed = identity(p['candidate']['directory'],regular(UNIT,limit=65536))
    need(all(observed[key] == p['candidate'][key] for key in ('installer_sha256','runtime_sha256','unit_sha256')))
    sealed_candidate(p['candidate'])
    output = subprocess.run(['systemctl','show','--property=ActiveState,MainPID,ControlPID','ultra-ansible-controller.service'],
                            check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5).stdout.decode()
    values = dict(line.split('=',1) for line in output.splitlines())
    need(values['ActiveState'] in ('inactive','failed') and values['MainPID'] == values['ControlPID'] == '0')
    auth = ROOT / ('recovery-controller-' + context['request_sha256'] + '.json')
    raw = json.dumps(recovery_authorization(context),sort_keys=True,separators=(',',':')).encode()
    if os.path.lexists(auth):
        need(json.loads(regular(auth,True,4096)) == recovery_authorization(context))
    else:
        fd = os.open(auth,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        fd=os.open(ROOT,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    path=UNIT.parent/'ultra-ansible-controller.service.d/90-retained-primary.conf'
    content=('[Unit]\nRefuseManualStart=no\nConditionPathExists='+str(auth)+'\n').encode()
    need(regular(path,limit=4096) in (recovery_blocked().encode(),content))
    fd,name=tempfile.mkstemp(prefix='.recovery-controller-',dir=path.parent)
    try:
        os.fchmod(fd,0o644)
        with os.fdopen(fd,'wb') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
        os.replace(name,path);fd=os.open(path.parent,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
    finally:
        if os.path.lexists(name):os.unlink(name)
    return p['proof']


def prepared_tools_inventory(request, preparation_sha):
    """Derive the live tools predecessor from the manifest-authenticated archive.

    The original app manifest is deliberately not used for this prepared-only
    identity. No claimed subset of a stored inventory may hide member drift.
    """
    release = Path(request['tools_release_directory'])
    raw = regular(release / 'release-manifest.json', limit=1048576)
    need(digest(raw) == request['tools_manifest_sha256'])
    manifest = json.loads(raw)
    assets = [asset for asset in manifest['assets'] if asset['name'] == 'ultra-recovery.tar.gz']
    need(len(assets) == 1)
    archive = regular(release / 'ultra-recovery.tar.gz', limit=32*1024*1024)
    need(len(archive) == assets[0]['size'] and digest(archive) == assets[0]['sha256'])
    expected = {}; hashes = {}; seen = set(); total = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as stream:
        for member in stream:
            need(member.isfile() and (member.name == 'ssh_policy.json' or
                 re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]+\.(py|service|timer)',member.name))
                 and member.name not in seen and len(seen)<64 and 0<=member.size<=4*1024*1024)
            seen.add(member.name); total += member.size; need(total<=32*1024*1024)
            data = stream.extractfile(member).read(member.size+1); need(len(data)==member.size)
            if member.name.startswith('test_'): continue
            checksum = digest(data); hashes[member.name] = checksum
            expected['/opt/ultra-recovery/'+member.name] = checksum
            if member.name.endswith(('.service', '.timer')):
                expected['/etc/systemd/system/'+member.name] = checksum
    need(all(name in hashes for name in ['recovery.py','db_connection.py','reconcile.py','monitor.py','heartbeat.py',
                                        'ultra-recovery-backup.service','ultra-recovery-backup.timer','ssh_policy.json']))
    suspension = json.loads(regular('/etc/ultra-recovery/preparation-suspension.json', True, 1048576))
    need(suspension.get('protocol') == 'ultra-recovery-preparation-suspension-v1'
         and suspension.get('request_sha256') == preparation_sha
         and suspension.get('tools_manifest_sha256') == request['tools_manifest_sha256']
         and suspension.get('active_inventory') == expected)
    for path, checksum in expected.items(): need(digest(regular(path)) == checksum)
    return hashes


def prepared_schedules_restored(request, preparation_sha):
    path = Path('/etc/ultra-recovery/preparation-schedules-restored.json')
    if not os.path.lexists(path):
        return False
    restored = json.loads(regular(path, True, 65536))
    raw = regular('/etc/ultra-recovery/preparation-suspension.json', True, 1048576)
    suspension = json.loads(raw)
    need(restored == {'protocol':'ultra-recovery-preparation-schedules-restored-v1',
         'request_sha256':preparation_sha,'suspension_sha256':digest(raw)}
         and suspension.get('request_sha256') == preparation_sha
         and suspension.get('tools_manifest_sha256') == request['tools_manifest_sha256']
         and bool(suspension.get('active_inventory')))
    for path, checksum in suspension['active_inventory'].items():
        need(path.startswith(('/opt/ultra-recovery/','/etc/systemd/system/')) and digest(regular(path)) == checksum)
    for name in ['ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']:
        need(not os.path.lexists(UNIT.parent / (name + '.d') / '90-retained-primary.conf'))
    for name in ['ultra-recovery-backup.service','ultra-recovery-reconcile.service']:
        need(digest(regular(UNIT.parent / (name + '.d') / '95-deployment-background.conf')) == suspension['background_gate_sha256'])
    return True


def prepared_policy(p):
    """Authenticate the post-handoff exception from existing protected records.

    A claimed policy never falls back to ordinary rollback authorization.
    This does not authorize opening or starting a retained controller.
    """
    policy = p.get('prepared_policy', {})
    if not policy:
        return False
    need(isinstance(policy, dict) and set(policy) == {'policy','envelope_sha256','preparation_sha256','handoff_sha256',
         'enforcement_sha256','operation_id','source_id','scope_sha256','plan_sha256','inventory_sha256',
         'manifest_sha256','baseline_manifest_sha256','candidate'} and policy.get('policy') == 'retain-prepared-candidate'
         and not p.get('recovery_request_sha256'))
    operations = ROOT / 'deploy-operations'
    current = json.loads(regular(operations / 'current.json', True, 4096))
    envelope_sha = current.get('request_sha256', '')
    need(current.get('schema') == 1 and SHA.fullmatch(envelope_sha)
         and policy.get('envelope_sha256') == envelope_sha)
    directory = operations / envelope_sha
    raw = regular(directory / 'request.json', True, 1048576)
    need(digest(raw) == envelope_sha)
    envelope = json.loads(raw)
    state = json.loads(regular(directory / 'state.json', True, 4096))
    need(envelope.get('schema') == 2 and state.get('request_sha256') == envelope_sha
         and state.get('state') == 'running' and state.get('stage') == 'upgrade'
         and any(line.endswith(':/system.slice/ultra-deploy-' + envelope_sha + '.service')
                 for line in Path('/proc/self/cgroup').read_text().splitlines()))
    request = envelope['preparation']
    state_dir = Path(request['state_directory'])
    raw = regular(state_dir / 'request.json', True, 1048576)
    need(json.loads(raw) == request and digest(raw) == policy.get('preparation_sha256')
         and request.get('protocol') == 'ultra-recovery-preparation-request-v1')
    for field, checksum in [('config_path','config_sha256'),('upgrade_config_path','upgrade_config_sha256'),
                            ('baseline_manifest_path','baseline_manifest_sha256'),('known_hosts_path','known_hosts_sha256')]:
        need(digest(regular(request[field])) == request[checksum])
    need(digest(regular(Path(request['tools_release_directory']) / 'release-manifest.json')) == request['tools_manifest_sha256'])
    need(request['tools_manifest_sha256'] == p['manifest_sha256'] == policy.get('manifest_sha256')
         and request['baseline_manifest_sha256'] == policy.get('baseline_manifest_sha256'))
    admission = recovery_admission(request, policy['preparation_sha256'])
    need(json.loads(regular(ROOT / 'recovery-preparation-admission.json', True, 4096)) == admission
         and json.loads(regular(ROOT / 'retained-primary-admission.json', True, 4096)) ==
         {'protocol':'retained-primary-admission-v1','binding_sha256':request['retained_fence_sha256']}
         and not os.path.lexists(ROOT / 'retained-primary-admission-open'))
    prepared_tools_inventory(request, policy['preparation_sha256'])
    if not prepared_schedules_restored(request, policy['preparation_sha256']):
        for name in ['ultra-recovery-reconcile.service','ultra-recovery-reconcile.timer']:
            need(regular(UNIT.parent / (name + '.d') / '90-retained-primary.conf', limit=4096).decode() == recovery_blocked())
    raw = regular(state_dir / 'broker-handoff.json', True, 1048576)
    need(digest(raw) == policy.get('handoff_sha256'))
    terminal = json.loads(raw)
    descriptor = json.loads(regular(state_dir / 'broker-preflight.json', True, 1048576))
    need(terminal.get('protocol') == 'ultra-recovery-broker-handoff-v1' and terminal.get('verified') is True
         and terminal.get('request_sha256') == policy['preparation_sha256'] and terminal.get('preflight') == descriptor
         and descriptor.get('protocol') == 'ultra-recovery-broker-preflight-v1'
         and descriptor.get('request_sha256') == policy['preparation_sha256'])
    for key in ['operation_id','source_id','scope_sha256','plan_sha256','inventory_sha256','enforcement_sha256']:
        need(descriptor.get(key) == policy.get(key))
    need(policy['operation_id'] == p['operation_id'] and policy['scope_sha256'] == p['scope_sha256']
         and policy.get('candidate') == p['candidate'] and descriptor['source_id'] == p['proof']['source_lifecycle']['id'])
    planned = Path(descriptor['directory'])
    need(planned.parent == ROOT and digest(regular(planned / 'operator-plan.json', True)) == policy['plan_sha256']
         and digest(regular(planned / 'recovery-upgrade-inventory.json', True)) == policy['inventory_sha256'])
    raw = regular(planned / 'controller-enforcement.json', True, 1048576)
    need(digest(raw) == policy['enforcement_sha256'] and json.loads(raw) == p['proof'])
    job = state_dir / 'ansible-broker-handoff'
    receipt_raw = regular(job / 'receipt.json', True, 1048576)
    receipt = json.loads(receipt_raw)
    job_raw = regular(job / 'job.json', True, 1048576); metadata = json.loads(job_raw)
    request_raw = regular(job / 'request.json', True, 1048576)
    complete = json.loads(regular(job / 'execution-completion.json', True, 1048576))
    need(receipt.get('state') == 'succeeded' and receipt.get('result',{}).get('verified') is True
         and receipt['result'].get('request_sha256') == policy['preparation_sha256']
         and metadata.get('operation') == 'handoff-recovery-controller'
         and metadata.get('request_sha256') == receipt.get('request_sha256') == digest(request_raw)
         and metadata.get('binary_sha256') == receipt.get('binary_sha256')
         and complete.get('outcome') == 'succeeded' and complete.get('local_cleanup') is True
         and complete.get('receipt_sha256') == digest(receipt_raw)
         and complete.get('fence',{}).get('job_directory') == str(job)
         and complete['fence'].get('job_sha256') == digest(job_raw)
         and complete['fence'].get('request_sha256') == digest(request_raw)
         and complete['fence'].get('operation') == 'handoff-recovery-controller')
    ack_name = terminal.get('acknowledgement','')
    need(Path(ack_name).name == ack_name and ack_name.startswith('broker-handoff-ack-'))
    ack = json.loads(regular(state_dir / ack_name, True, 65536))
    need(ack.get('protocol') == 'ultra-recovery-broker-ack-v1' and ack.get('request_sha256') == policy['preparation_sha256']
         and ack.get('operation_id') == p['operation_id'] and ack.get('scope_sha256') == p['scope_sha256'])
    # Rechecking the exact instance prevents a new broker from inheriting an old ack.
    out = subprocess.run(['systemctl','show','--property=MainPID','ultra-ansible-controller.service'],
                         check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5).stdout.decode().strip()
    pid = out.removeprefix('MainPID=')
    need(pid.isdigit() and int(pid) > 1)
    proc = Path('/proc') / pid
    instance = {'pid':pid,'start_time':(proc/'stat').read_text().rsplit(')',1)[1].split()[19],
                'installer_sha256':digest((proc/'exe').read_bytes()),'unit_sha256':digest(regular(UNIT,limit=65536))}
    need(ack.get('instance') == instance)
    live = live_identity()
    need(all(live[key] == p['candidate'][key] for key in ('directory','installer_sha256','runtime_sha256','unit_sha256')))
    sealed_candidate(p['candidate'])
    latest = subprocess.run(['systemctl','show','--property=MainPID','ultra-ansible-controller.service'],
                            check=True,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=5).stdout.decode().strip()
    need(latest == out and (proc/'stat').read_text().rsplit(')',1)[1].split()[19] == instance['start_time'])
    return True


def execute(p):
    need(canonical_id(p['operation_id']) and SHA.fullmatch(p['scope_sha256'])
         and SHA.fullmatch(p['manifest_sha256']))
    validate_candidate(p['candidate'])
    retain_prepared = prepared_policy(p)
    recovery = recovery_context(p.get('recovery_request_sha256',''),p['operation_id'],p['candidate'],p['manifest_sha256'])
    if p['action'] == 'open-recovery':
        return open_recovery_controller(p,recovery)
    if p['action'] == 'probe' and not p['proof']:
        raw, ledger, _, lifecycle = snapshot(ROOT)
        need(lifecycle['phase'] == 'released')
        rollback = live_identity(recovery, recovery is not None)
        candidate_raw = regular(p['candidate_executable'])
        need(digest(candidate_raw) == p['candidate']['installer_sha256'])
        probe(p['candidate_executable'], ledger)
        probe(Path(rollback['directory']) / 'ultra-install', ledger)
        need(snapshot(ROOT)[0] == raw and snapshot(ROOT)[3] == lifecycle and live_identity(recovery, recovery is not None) == rollback
             and digest(regular(p['candidate_executable'])) == p['candidate']['installer_sha256'])
        proof = {'schema': 1, 'operation_id': p['operation_id'], 'scope_sha256': p['scope_sha256'],
                 'manifest_sha256': p['manifest_sha256'], 'machine_sha256': machine_sha(),
                 'ledger_sha256': digest(raw), 'source_lifecycle': lifecycle,
                 'candidate': p['candidate'], 'rollback': rollback}
    else:
        proof = p['proof']
        lifecycle = verify(proof, p['operation_id'], p['scope_sha256'], p['manifest_sha256'],
                           p['candidate'], p['phase'])
        if retain_prepared:
            need(lifecycle == {'id':p['operation_id'],'phase':'applying'} or
                 lifecycle == {'id':p['operation_id'],'phase':'checking'})
        old = proof['rollback']
        selected = p['candidate']
        if p['phase'] == 'staged':
            transition_identity(proof, recovery)
            need(CURRENT.is_symlink() and os.readlink(CURRENT) == selected['directory'])
            live = identity(selected['directory'], regular(UNIT, limit=65536))
        else:
            try:
                live = live_identity(recovery, recovery is not None and p['phase'] in ('preflight','reserved','before'))
            except ValueError:
                need(p['phase'] in ('preflight', 'reserved', 'before'))
                transition_identity(proof, recovery)
                live = None
        old_selected = live == old
        candidate_selected = live is not None and all(live[key] == selected[key] for key in ('directory', 'installer_sha256', 'runtime_sha256', 'unit_sha256'))
        need(live is None or old_selected or candidate_selected)
        version = Path(selected['directory']).name.removeprefix('managed-')
        need(re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', version))
        fallback = ROOT / 'releases' / version / 'controller.service.previous'
        if os.path.lexists(fallback):
            need(digest(regular(fallback, limit=65536)) == old['unit_sha256'])
        else:
            need(old_selected)
        if candidate_selected:
            need(intent_present(proof))
            sealed_candidate(selected)
        if p['phase'] in ('candidate', 'completion'):
            need(candidate_selected)
        elif p['phase'] == 'rollback':
            need(candidate_selected if retain_prepared else old_selected)
        elif p['phase'] == 'preflight' and lifecycle['phase'] == 'released':
            need(old_selected)
        if p['phase'] == 'before':
            save_intent(proof)
        # Hashing immutable trees may take time. Recheck the live floor and
        # lifecycle after identity inspection, before returning authorization.
        latest_raw, _, _, latest_lifecycle = snapshot(ROOT)
        need(digest(latest_raw) == proof['ledger_sha256'] and latest_lifecycle == lifecycle)
    return proof


def main():
    from ansible.module_utils.basic import AnsibleModule
    module = AnsibleModule(argument_spec={
        'action': {'type': 'str', 'choices': ['probe', 'verify', 'open-recovery'], 'required': True},
        'operation_id': {'type': 'str', 'required': True},
        'scope_sha256': {'type': 'str', 'required': True},
        'manifest_sha256': {'type': 'str', 'required': True},
        'candidate': {'type': 'dict', 'required': True},
        'candidate_executable': {'type': 'path'},
        'recovery_request_sha256': {'type':'str','default':''},
        'prepared_policy': {'type':'dict','default':{}},
        'proof': {'type': 'dict', 'default': {}},
        'phase': {'type': 'str', 'choices': ['preflight', 'reserved', 'before', 'staged', 'candidate', 'rollback', 'completion'], 'default': 'reserved'},
    }, supports_check_mode=True)
    try:
        need(os.geteuid() == 0 and not module.check_mode)
        p = module.params
        publishing = p['action'] == 'verify' and p['phase'] == 'before'
        existed = publishing and intent_present(p['proof'])
        proof = execute(module.params)
        module.exit_json(changed=publishing and not existed, verified=True, proof=proof,
                         prepared_schedules_suspended=bool(p.get('prepared_policy')) and not os.path.lexists('/etc/ultra-recovery/preparation-schedules-restored.json'),
                         completion_ready=p['phase'] == 'completion' and snapshot(ROOT)[3] ==
                         {'id': p['operation_id'], 'phase': 'released'})
    except (OSError, ValueError, KeyError, TypeError, configparser.Error, subprocess.SubprocessError):
        module.fail_json(msg='controller_enforcement_migration_unverified')


if __name__ == '__main__':
    main()
