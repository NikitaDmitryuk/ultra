#!/usr/bin/env python3
"""Explicit operator deployment from clean, committed HEAD; never a scheduler."""
import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import ipaddress
import io
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time


class DeployError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise DeployError(code)


def run(command, cwd, stage, capture=False, env=None):
    # Installer and build tools may include private input values in their errors.
    # Expose only this wrapper's fixed stage and exit code, never their output.
    result = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, check=False, env=env)
    require(result.returncode == 0, stage + '_failed_exit_' + str(result.returncode))
    return result.stdout.decode().strip() if capture else None


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def private_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) == 0o600, 'canonical_config_requires_owned_regular_0600')
    return path.read_bytes()


def canonical_file(path):
    """Read the non-secret canonical deployment config in either supported mode."""
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
            stat.S_IMODE(info.st_mode) in (0o600, 0o644), 'canonical_config_requires_owned_regular_readable_file')
    return path.read_bytes()


def atomic_write(path, raw, preserve_mode=False):
    mode = 0o600
    if preserve_mode:
        try:
            info = path.lstat()
        except FileNotFoundError:
            pass
        else:
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                    stat.S_IMODE(info.st_mode) in (0o600, 0o644), 'canonical_config_mode_invalid')
            mode = stat.S_IMODE(info.st_mode)
    descriptor, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


@contextlib.contextmanager
def lock(path):
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and
                stat.S_IMODE(info.st_mode) == 0o600, 'manual_lock_not_private')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DeployError('manual_deploy_already_running') from None
        yield
    finally:
        os.close(descriptor)


def canonical_config_lock(path):
    resolved = Path(path).resolve(strict=True)
    return resolved.with_name('.' + resolved.name + '.manual-deploy.lock')


def config_candidate(raw, version, release):
    replacements = {'ULTRA_AUTOMATION_VERSION': version, 'ULTRA_AUTOMATION_RELEASE_DIR': str(release)}
    seen = set()
    lines = []
    for line in raw.decode().splitlines(keepends=True):
        match = re.match(r'^\s*(ULTRA_AUTOMATION_(?:VERSION|RELEASE_DIR))\s*=', line)
        if match:
            key = match[1]
            require(key not in seen, 'duplicate_canonical_release_key')
            seen.add(key)
            line = key + '=' + json.dumps(replacements[key], ensure_ascii=True) + '\n'
        lines.append(line)
    text = ''.join(lines)
    if text and not text.endswith('\n'):
        text += '\n'
    for key in replacements:
        if key in seen:
            continue
        text += key + '=' + json.dumps(replacements[key], ensure_ascii=True) + '\n'
    return text.encode()


def remote_attempt(config, version):
    # Normalize derived release fields to avoid hashing a path that contains
    # this very hash. Corrections to any other canonical input get a new kit;
    # retries using the already-updated config retain the same attempt identity.
    return sha(config_candidate(config, version, '/manual-release'))


def validate_config_policy(raw):
    # Match installplan.DisallowedDeploymentSecret before creating any backup,
    # temporary input, or remote copy. The exact built Go parser runs below too.
    forbidden = {'TELEGRAM_BOT_TOKEN', 'ULTRA_VULTR_API_KEY', 'ULTRA_VULTR_DNS_API_KEY',
                 'ULTRA_CUTOVER_SUBSCRIPTION_URL', 'ULTRA_RELAY_ADMIN_TOKEN', 'ULTRA_DB_DSN'}
    for line in raw.decode().splitlines():
        if not line.strip() or line.lstrip().startswith('#') or '=' not in line:
            continue
        key = line.split('=', 1)[0].strip().upper()
        signing = any(word in key for word in ['MINISIGN', 'SIGNING'])
        private = any(word in key for word in ['SECRET', 'PRIVATE', 'PASSWORD', 'PASSPHRASE'])
        require(key not in forbidden and not (signing and private), 'canonical_config_contains_forbidden_secret')
        require(not key.startswith('ULTRA_AUTO_UPGRADE_'), 'canonical_config_contains_removed_policy')


def verify_bundle(source, bundle, commit, version):
    require(not bundle.is_symlink() and bundle.is_dir(), 'candidate_not_regular_directory')
    manifest_path = bundle / 'release-manifest.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink(), 'candidate_manifest_not_regular')
    manifest = json.loads(manifest_path.read_bytes())
    require(manifest.get('source_commit') == commit and manifest.get('version') == version,
            'candidate_identity_mismatch')
    rows = manifest.get('assets', [])
    require(len(rows) == 14 and len({row['name'] for row in rows}) == 14,
            'candidate_requires_14_assets')
    require({path.name for path in bundle.iterdir()} <= {row['name'] for row in rows} |
            {'release-manifest.json', 'candidate.json'}, 'candidate_unexpected_inventory')
    for row in rows:
        name = row['name']
        require(isinstance(name, str) and Path(name).name == name, 'candidate_asset_name_invalid')
        path = bundle / name
        require(not path.is_symlink() and path.is_file(), 'candidate_asset_not_regular')
    # Reuse the release contract from the exact source commit: ELF architectures,
    # full source archives, all 14 manifest hashes, checksum inventory, and locked
    # offline wheels for both architectures and Python 3.12/3.13/3.14.
    spec = importlib.util.spec_from_file_location('release_contract', source / 'scripts/test-release-assets.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.validate_bundle(bundle, (source / '.github/workflows/release.yml').read_text())


def prepare_runtime_environment(repo, source):
    environment = os.environ.copy()
    # Never inherit an unchecked runtime override into a candidate build.
    environment.pop('ULTRA_VERIFIED_RUNTIME_DIR', None)
    cached = repo / 'dist'
    if (cached / 'release-manifest.json').is_file():
        spec = importlib.util.spec_from_file_location('manual_runtime', source / 'scripts/manual-deploy-runtime.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.validate_pair(cached, source / 'deploy/ansible/requirements.txt')
        frozen = source / '.manual-runtime-inputs'
        frozen.mkdir(mode=0o700)
        for name in ['release-manifest.json', 'checksums.txt', 'ultra-ansible-runtime-linux-amd64.tar.gz', 'ultra-ansible-runtime-linux-arm64.tar.gz']:
            shutil.copyfile(cached / name, frozen / name)
        module.validate_pair(frozen, source / 'deploy/ansible/requirements.txt')
        environment['ULTRA_VERIFIED_RUNTIME_DIR'] = str(frozen)
    else:
        run([sys.executable, '-m', 'pip', '--version'], repo, 'pip_prerequisite')
    return environment


def build_candidate(repo, root, commit, version):
    bundle = root / version
    with tempfile.TemporaryDirectory(prefix='.source-', dir=root) as temporary:
        source = Path(temporary) / 'source'
        run(['git', 'clone', '--quiet', '--no-hardlinks', '--no-checkout', str(repo), str(source)], repo, 'source_clone')
        run(['git', 'checkout', '--quiet', '--detach', commit], source, 'source_checkout')
        if bundle.exists() or bundle.is_symlink():
            identity_path = bundle / 'candidate.json'
            require(identity_path.is_file() and not identity_path.is_symlink(), 'candidate_identity_missing')
            identity = json.loads(identity_path.read_bytes())
            require(identity == {'schema': 1, 'commit': commit, 'version': version,
                    'manifest_sha256': sha((bundle / 'release-manifest.json').read_bytes())}, 'candidate_identity_mismatch')
            verify_bundle(source, bundle, commit, version)
            return bundle
        environment = prepare_runtime_environment(repo, source)
        run(['make', 'release-dist'], source, 'release_build', env=environment)
        run(['bash', 'scripts/build-release-manifest.sh', 'dist', version], source, 'manifest_build')
        verify_bundle(source, source / 'dist', commit, version)
        pending = Path(tempfile.mkdtemp(prefix='.candidate-', dir=root))
        try:
            shutil.copytree(source / 'dist', pending, dirs_exist_ok=True)
            verify_bundle(source, pending, commit, version)
            (pending / 'candidate.json').write_text(json.dumps({'schema': 1, 'commit': commit, 'version': version,
                'manifest_sha256': sha((pending / 'release-manifest.json').read_bytes())}))
            for path in pending.iterdir():
                require(path.is_file() and not path.is_symlink(), 'candidate_unexpected_file')
                path.chmod(0o500 if path.name.startswith('ultra-') and '-linux-' in path.name and not path.name.endswith('.gz') else 0o400)
            pending.chmod(0o500)
            os.rename(pending, bundle)
        finally:
            if pending.exists():
                pending.chmod(0o700)
                shutil.rmtree(pending)
    return bundle


def config_values(raw):
    # Parse literals only; never source the deployment file or interpolate it.
    values = {}
    for line in raw.decode().splitlines():
        if not line.strip() or line.lstrip().startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        tokens = shlex.split(value, comments=True)
        require(len(tokens) <= 1 and key.strip() not in values, 'operator_config_literal_required')
        values[key.strip()] = tokens[0] if tokens else ''
    return values


def operator_transport(path, config):
    values = config_values(config)
    bridge_address = values.get('BRIDGE_SSH_HOST') or values.get('BRIDGE') or values.get('FRONT')
    static = json.loads(values.get('ULTRA_AUTOMATION_STATIC_NODES', '[]'))
    local_identity = os.environ.get('ULTRA_OPERATOR_IDENTITY')
    local_pins = os.environ.get('ULTRA_OPERATOR_KNOWN_HOSTS')
    if path:
        require(not local_identity and not local_pins, 'operator_transport_sources_conflict')
        path = Path(path)
        require(path.is_absolute() and path.name == 'inventory.json' and path.parent.name == 'compare'
                and path.parent.parent.name.startswith('adopt-'), 'operator_generated_inventory_required')
        raw = private_file(path)
        request = private_file(path.with_name('request.json'))
        job = json.loads(private_file(path.with_name('job.json')))
        inventory = json.loads(raw)
        require(json.loads(request).get('inventory') == inventory and job.get('operation') == 'adopt'
                and job.get('request_sha256') == sha(request), 'operator_inventory_provenance_invalid')
        all_hosts = inventory['all']
        common = all_hosts['vars']
        bridge = all_hosts['children']['bridge']['hosts']['bridge']
        exits = all_hosts['children']['exits']['hosts']
        source_binding = sha(raw)
    else:
        require(local_identity and local_pins, 'operator_identity_and_pins_required')
        require(static, 'operator_static_jump_required')
        # Local credential references supplement the single canonical topology;
        # they are never written to install.config or sent to the bridge.
        common = {'ansible_user': 'root', 'ansible_ssh_private_key_file': local_identity,
                  'ansible_ssh_common_args': shlex.join(['-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes',
                                                       '-o', 'UserKnownHostsFile=' + local_pins])}
        bridge = {'ansible_host': bridge_address}
        exits = {'exit_' + str(index): {'ansible_host': node['address']} for index, node in enumerate(static)}
        source_binding = sha(json.dumps({'bridge': bridge_address, 'static': [n['address'] for n in static]}, sort_keys=True).encode())
    require(bridge.get('ansible_host') == bridge_address and bridge_address == values.get('BRIDGE')
            and static and {n['address'] for n in static} == {n['ansible_host'] for n in exits.values()}
            and 'exit_0' in exits, 'operator_inventory_topology_changed')

    def endpoint(host):
        settings = dict(common, **host)
        address = settings['ansible_host']
        ipaddress.ip_address(address)  # aliases cannot import local SSH configuration
        require(settings.get('ansible_user') == 'root', 'operator_root_transport_required')
        identity = Path(settings['ansible_ssh_private_key_file'])
        require(identity.is_absolute(), 'operator_identity_absolute_required')
        # Inspect identity ownership/mode only. SSH opens the private key itself.
        info = identity.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600, 'operator_identity_private_required')
        identity_binding = [str(identity), info.st_ino, info.st_size, info.st_mtime_ns]
        options = shlex.split(settings.get('ansible_ssh_args', '') + ' ' + settings['ansible_ssh_common_args'])
        pins = [token.split('=', 1)[1] for token in options if token.startswith('UserKnownHostsFile=')]
        require('StrictHostKeyChecking=yes' in options and 'IdentitiesOnly=yes' in options
                and len(pins) == 1, 'operator_explicit_pins_required')
        pin_path = Path(pins[0])
        require(pin_path.is_absolute(), 'operator_pins_absolute_required')
        pins_sha = sha(private_file(pin_path))
        probe = subprocess.run(['ssh-keygen', '-F', address, '-f', str(pin_path)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        require(probe.returncode == 0, 'operator_endpoint_pin_missing')
        argv = ['ssh', '-F', '/dev/null', '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes',
                '-o', 'StrictHostKeyChecking=yes', '-o', 'UpdateHostKeys=no',
                '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'ProxyJump=none',
                '-o', 'ConnectTimeout=15', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
                '-o', 'UserKnownHostsFile=' + str(pin_path),
                '-i', str(identity), '-p', '22']
        return argv, 'root@' + address, {'host': address, 'identity_file': identity_binding,
                                       'pins_file': str(pin_path), 'pins_sha256': pins_sha}

    target, destination, target_identity = endpoint(bridge)
    jump, jump_destination, jump_identity = endpoint(exits['exit_0'])
    target += ['-o', 'ProxyCommand=' + shlex.join(jump + ['-W', '%h:%p', jump_destination]), destination]
    binding = sha(json.dumps({'source_sha256': source_binding, 'target': target_identity,
                             'jump': jump_identity}, sort_keys=True).encode())
    return target, binding


def operator_requested():
    return any(os.environ.get(key) for key in ['ULTRA_OPERATOR_INVENTORY', 'ULTRA_OPERATOR_IDENTITY',
                                              'ULTRA_OPERATOR_KNOWN_HOSTS'])


# Executed only through pinned SSH. This helper never reads secret environment files.
# Stage into a fresh private sibling and rename only after every byte is checked.
REMOTE_PROGRAM = r'''
import fcntl,hashlib,json,os,platform,re,shutil,stat,sys,tarfile,tempfile
from pathlib import Path
def need(ok):
    if not ok: raise ValueError('remote_input_invalid')
def digest(data): return hashlib.sha256(data).hexdigest()
mode,commit,version,manifest_sha,config_sha,attempt=sys.argv[1:7]
need(re.fullmatch('[a-f0-9]{40}',commit) and version=='v0.0.'+str(int(commit,16)))
need(all(re.fullmatch('[a-f0-9]{64}',x) for x in [manifest_sha,config_sha,attempt]))
need(os.geteuid()==0)
parent=Path('/var/lib/ultra-ansible/operator-inputs')
for directory in [parent.parent,parent]:
    if not directory.exists(): directory.mkdir(mode=0o700)
    info=directory.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077)
root=parent/('manual-'+commit+'-'+attempt)
lock=os.open(parent/'manual-deploy.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
info=os.fstat(lock);need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600)
fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
def read(path):
    info=path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077)
    return path.read_bytes()
def verify(directory):
    info=directory.lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700)
    info=(directory/'release').lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700)
    raw=read(directory/'release/release-manifest.json');need(digest(raw)==manifest_sha)
    m=json.loads(raw);need(m['source_commit']==commit and m['version']==version and len(m['assets'])==14)
    names=set()
    for row in m['assets']:
        name=row['name'];need(re.fullmatch('[A-Za-z0-9_.-]+',name) and name not in ['.','..','release-manifest.json'] and name not in names)
        names.add(name);data=read(directory/'release'/name)
        need(len(data)==row['size'] and digest(data)==row['sha256'])
    need({x.name for x in (directory/'release').iterdir()}==names|{'release-manifest.json'})
    need({x.name for x in directory.iterdir()}=={'release','install.config'})
    need(digest(read(directory/'install.config'))==config_sha)
    return m
if mode=='stage':
    pending=Path(tempfile.mkdtemp(prefix='.manual-'+commit+'-',dir=parent))
    try:
        (pending/'release').mkdir(mode=0o700)
        seen=set();rows=None;total=0
        with tarfile.open(fileobj=sys.stdin.buffer,mode='r|') as archive:
            for member in archive:
                name=member.name
                need(member.isfile() and name not in seen)
                if name=='release/release-manifest.json':
                    need(not seen and member.size<=1048576)
                    raw=archive.extractfile(member).read();need(digest(raw)==manifest_sha)
                    m=json.loads(raw);need(m['source_commit']==commit and m['version']==version and len(m['assets'])==14)
                    rows={}
                    for row in m['assets']:
                        n=row['name'];need(re.fullmatch('[A-Za-z0-9_.-]+',n) and n not in ['.','..','release-manifest.json'] and n not in rows)
                        rows[n]=row
                else:
                    need(rows is not None)
                    if name=='install.config': need(member.size<=1048576)
                    else:
                        need(name.startswith('release/') and name[8:] in rows)
                        need(member.size==rows[name[8:]]['size'])
                    total+=member.size;need(total<=2147483648)
                    raw=None
                destination=pending/name
                fd=os.open(destination,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as output:
                    if raw is not None: output.write(raw)
                    else:
                        source=archive.extractfile(member)
                        shutil.copyfileobj(source,output,1048576)
                    output.flush();os.fsync(output.fileno())
                seen.add(name)
        need(rows is not None and seen=={'release/release-manifest.json','install.config'}|{'release/'+n for n in rows})
        verify(pending)
        for directory in [pending/'release',pending]:
            fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
        if root.exists() or root.is_symlink(): verify(root)
        else:
            os.rename(pending,root)
            fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY);os.fsync(fd);os.close(fd)
        architecture={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine());need(platform.system()=='Linux' and architecture)
        print(json.dumps({'architecture':architecture,'manifest_sha256':manifest_sha,'config_sha256':config_sha,'attempt':attempt}))
    finally:
        if pending.exists(): shutil.rmtree(pending)
elif mode=='run':
    verify(root)
    architecture=sys.argv[7];need(architecture in ['amd64','arm64'])
    need(architecture=={'x86_64':'amd64','aarch64':'arm64'}.get(platform.machine()))
    action=sys.argv[8];need(action in ['doctor','adoption_check','adoption_apply','upgrade','operator-upgrade','status'])
    retry_failed=len(sys.argv)>9 and sys.argv[9]=='1';need(len(sys.argv)<=9 or sys.argv[9] in ['0','1'])
    binary=root/'release'/('ultra-install-linux-'+architecture)
    binary.chmod(0o700)
    args={'doctor':['doctor'],'adoption_check':['adopt','--adopt-runtime','--bridge-native','--check','--release-dir',str(root/'release')],
          'adoption_apply':['apply','--adopt-runtime','--bridge-native'],
          'upgrade':['operator-upgrade','--release-dir',str(root/'release'),
              '--source-commit',commit,'--version',version,'--manifest-sha256',manifest_sha,
              '--config-sha256',config_sha] + (['--retry-failed'] if retry_failed else []),
          'status':['status']}[action]
    os.chdir(root)
    # Keep the remote lock across exec and strip unchecked installer overrides.
    os.set_inheritable(lock,True)
    environment={k:v for k,v in os.environ.items() if not k.startswith('ULTRA_') and k not in ['DATABASE_URL','PYTHONPATH','PYTHONHOME','ANSIBLE_CONFIG']}
    os.execve(binary,[str(binary)]+args+['--config',str(root/'install.config')],environment)
else: raise ValueError('remote_action_invalid')
'''


def remote_command(transport, commit, version, manifest_sha, config_sha, attempt, mode, *arguments):
    return transport + [shlex.join(['python3', '-I', '-c', REMOTE_PROGRAM, mode, commit,
                                  version, manifest_sha, config_sha, attempt, *arguments])]


def stage_remote(repo, root, bundle, config, transport, commit, version, manifest_sha):
    # A bounded on-disk stream avoids keeping release binaries in memory.
    with tempfile.TemporaryFile(dir=root) as stream:
        with tarfile.open(fileobj=stream, mode='w|') as archive:
            manifest = (bundle / 'release-manifest.json').read_bytes()
            require(sha(manifest) == manifest_sha, 'candidate_manifest_changed')
            for name in ['release-manifest.json'] + [row['name'] for row in json.loads(manifest)['assets']]:
                require(Path(name).name == name and not (bundle / name).is_symlink(), 'candidate_asset_name_invalid')
                archive.add(bundle / name, arcname='release/' + name, recursive=False)
            entry = tarfile.TarInfo('install.config')
            entry.size = len(config)
            archive.addfile(entry, io.BytesIO(config))
        stream.seek(0)
        attempt = remote_attempt(config, version)
        result = subprocess.run(remote_command(transport, commit, version, manifest_sha, sha(config), attempt, 'stage'),
                                cwd=repo, stdin=stream, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    require(result.returncode == 0, 'bridge_staging_failed')
    receipt = json.loads(result.stdout)
    require(receipt.get('architecture') in ['amd64', 'arm64'] and receipt.get('manifest_sha256') == manifest_sha
            and receipt.get('config_sha256') == sha(config) and receipt.get('attempt') == attempt, 'bridge_staging_receipt_invalid')
    return receipt['architecture']


def rollout(repo, root, bundle, commit, version, adopt, config_path=None, retry_failed=False):
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    require(platform.system() == 'Linux' and architecture, 'operator_requires_linux_amd64_or_arm64')
    config = Path(config_path) if config_path else repo / 'install.config'
    current = canonical_file(config)
    validate_config_policy(current)
    operator_inventory = os.environ.get('ULTRA_OPERATOR_INVENTORY')
    transport, transport_binding = operator_transport(operator_inventory, current) if operator_requested() else (None, None)
    if transport:
        # plan only parses/validates policy; unlike doctor it never opens the
        # secrets file. Suppress its output because the plan contains inputs.
        run([str(bundle / ('ultra-install-linux-' + architecture)), 'plan', '--config', str(config), '--format', 'json'],
            repo, 'canonical_policy')
    attempt = remote_attempt(current, version) if transport else None
    remote_release = Path('/var/lib/ultra-ansible/operator-inputs') / ('manual-' + commit + '-' + (attempt or '')) / 'release'
    manifest_sha = sha((bundle / 'release-manifest.json').read_bytes()) if transport else None
    journal = root / 'operation.json'
    backup = root / ('install.config.before-' + version + '-' + str(time.time_ns()))
    new = config_candidate(current, version, remote_release if transport else bundle)
    if journal.exists():
        record = json.loads(private_file(journal))
        backup_name = record.get('backup', '')
        require(re.fullmatch(r'install\.config\.before-' + re.escape(version) + r'-[0-9]+', backup_name), 'manual_backup_identity_invalid')
        backup = root / backup_name
        require(record.get('commit') == commit and record.get('version') == version and
                record.get('adopt') == adopt, 'conflicting_unfinished_manual_operation')
        require(record.get('transport_binding') == transport_binding and record.get('manifest_sha256') == manifest_sha,
                'manual_operation_transport_or_manifest_changed')
        require(record.get('remote_attempt') == attempt, 'manual_operation_attempt_changed')
        if record.get('stage') == 'prepared' and sha(current) == record.get('previous_sha256'):
            atomic_write(config, new, preserve_mode=True)
        else:
            require(sha(current) == record.get('config_sha256'), 'canonical_config_changed_during_operation')
    else:
        atomic_write(backup, current)
        record = {'schema': 1, 'commit': commit, 'version': version, 'adopt': adopt,
                  'backup': backup.name, 'previous_sha256': sha(current), 'config_sha256': sha(new), 'stage': 'prepared', 'mutator_dispatched': False,
                  'transport_binding': transport_binding, 'manifest_sha256': manifest_sha, 'remote_attempt': attempt}
        atomic_write(journal, json.dumps(record).encode())
        require(canonical_file(config) == current, 'canonical_config_changed_before_update')
        atomic_write(config, new, preserve_mode=True)
    installer = str(bundle / ('ultra-install-linux-' + architecture))
    commands = [('doctor', [installer, 'doctor', '--config', str(config)])]
    if adopt:
        commands += [('adoption_check', [installer, 'adopt', '--config', str(config), '--release-dir', str(bundle), '--adopt-runtime', '--check']),
                     ('adoption_apply', [installer, 'apply', '--config', str(config), '--adopt-runtime'])]
    else:
        commands += [('upgrade', [installer, 'operator-upgrade', '--config', str(config), '--release-dir', str(bundle),
                                  '--source-commit', commit, '--version', version,
                                  '--manifest-sha256', manifest_sha or sha((bundle / 'release-manifest.json').read_bytes()),
                                  '--config-sha256', sha(new)])]
        if retry_failed:
            commands[-1][1].append('--retry-failed')
    commands += [('status', [installer, 'status', '--config', str(config)])]
    try:
        if transport:
            record['stage'] = 'bridge_staging'
            atomic_write(journal, json.dumps(record).encode())
            staged_config = canonical_file(config)
            require(sha(staged_config) == record['config_sha256'], 'canonical_config_changed_before_staging')
            staged_architecture = stage_remote(repo, root, bundle, staged_config, transport, commit, version, manifest_sha)
            require(record.get('remote_architecture', staged_architecture) == staged_architecture, 'bridge_architecture_changed')
            record['remote_architecture'] = staged_architecture
        for stage, command in commands:
            record['stage'] = stage
            if stage in ('adoption_apply', 'upgrade'):
                record['mutator_dispatched'] = True
            atomic_write(journal, json.dumps(record).encode())
            print('manual-deploy: ' + stage, flush=True)
            if transport:
                command = remote_command(transport, commit, version, manifest_sha, record['config_sha256'], attempt,
                                         'run', record['remote_architecture'], stage, '1' if retry_failed else '0')
            run(command, repo, stage)
    except BaseException:
        # Read-only adoption comparison cannot have dispatched a mutating job.
        # After apply/upgrade dispatch, keep exact canonical inputs for recovery.
        if not record.get('mutator_dispatched', False) and record['stage'] in ('bridge_staging', 'doctor', 'adoption_check') and sha(canonical_file(config)) == record['config_sha256']:
            previous = private_file(backup)
            require(sha(previous) == record['previous_sha256'], 'canonical_backup_changed')
            atomic_write(config, previous, preserve_mode=True)
            journal.unlink()
        else:
            print('manual-deploy: canonical inputs retained; reconcile the unfinished operation with ultra-install status before recovery; do not deploy another commit', file=sys.stderr)
        raise
    journal.unlink()


def main():
    require(__debug__, 'python_optimization_disables_release_validation')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-only', action='store_true', help='verify/build candidate without changing canonical config or remote hosts')
    parser.add_argument('--config', help='canonical install.config path; defaults to install.config in this checkout')
    parser.add_argument('--retry-failed', action='store_true', help='explicitly retry the same failed upgrade after recovery preflight')
    arguments = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    config = Path(os.path.abspath(arguments.config)) if arguments.config else repo / 'install.config'
    for executable in ['git', 'make', 'go', 'tar', 'sha256sum', 'bash']:
        require(shutil.which(executable), 'missing_prerequisite_' + executable)
    dirty = run(['git', 'status', '--porcelain', '--untracked-files=no'], repo, 'tracked_tree_check', capture=True)
    require(not dirty, 'tracked_tree_dirty_commit_before_deploy')
    commit = run(['git', 'rev-parse', '--verify', 'HEAD'], repo, 'source_commit', capture=True)
    require(re.fullmatch('[0-9a-f]{40}', commit), 'source_commit_invalid')
    require(os.environ.get('ADOPT', '0') in ('0', '1'), 'ADOPT_must_be_0_or_1')
    require(not arguments.retry_failed or os.environ.get('ADOPT') != '1', 'retry_failed_requires_upgrade')
    version = 'v0.0.' + str(int(commit, 16))
    root = repo / 'dist' / 'manual'
    require(not (repo / 'dist').is_symlink(), 'dist_must_not_be_symlink')
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    require(not root.is_symlink() and root.stat().st_uid == os.geteuid() and
            stat.S_IMODE(root.stat().st_mode) == 0o700, 'manual_state_requires_owned_0700')
    with lock(root / 'deploy.lock'):
        bundle = build_candidate(repo, root, commit, version)
        print('manual-deploy: verified ' + version, flush=True)
        if not arguments.build_only:
            require(not run(['git', 'status', '--porcelain', '--untracked-files=no'], repo, 'tracked_tree_recheck', capture=True), 'tracked_tree_changed_during_build')
            require(run(['git', 'rev-parse', '--verify', 'HEAD'], repo, 'source_commit_recheck', capture=True) == commit, 'HEAD_changed_during_build')
            with lock(canonical_config_lock(config)):
                current = canonical_file(config)
                validate_config_policy(current)
                if operator_requested():
                    for executable in ['ssh', 'ssh-keygen']:
                        require(shutil.which(executable), 'missing_prerequisite_' + executable)
                    operator_transport(os.environ.get('ULTRA_OPERATOR_INVENTORY'), current)
                rollout(repo, root, bundle, commit, version, os.environ.get('ADOPT') == '1', config, arguments.retry_failed)
    print('manual-deploy: complete', flush=True)


if __name__ == '__main__':
    try:
        main()
    except (DeployError, OSError, ValueError, AssertionError, KeyError, TypeError) as error:
        # Contract exceptions can include private paths; only our fixed codes are public.
        print('manual-deploy: ' + (str(error) if isinstance(error, DeployError) else 'local_validation_failed'), file=sys.stderr)
        sys.exit(1)
