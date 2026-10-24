#!/usr/bin/env python3
"""Verify the current recovery tools independently of the application baseline."""
import hashlib
import configparser
import shlex
import subprocess
import io
import json
import os
from pathlib import Path
import platform
import re
import stat
import tarfile

ROOT = Path('/opt/ultra-recovery')
SYSTEM = Path('/etc/systemd/system')
CURRENT = Path('/opt/ultra-ansible/current')
RETENTION = Path('/var/lib/ultra-ansible/retention')
NAMES = ('tools-manifest.json', 'tools.tar.gz', 'tools-inventory.json')
SYSTEMD_SUFFIXES = ('.service', '.timer')


def recovery_member_allowed(name):
    if name == 'ssh_policy.json':
        return True
    return bool(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]+\.(py|service|timer)', name))


def recovery_member_is_systemd_unit(name):
    return name.endswith(SYSTEMD_SUFFIXES)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path, private=False, maximum=32 * 1024 * 1024):
    path = Path(path)
    if any(item.is_symlink() for item in (path, *path.parents)):
        raise ValueError('recovery_tools_identity_unsafe')
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.geteuid()
            or info.st_mode & (0o077 if private else 0o022) or info.st_size > maximum):
        raise ValueError('recovery_tools_identity_unsafe')
    return path.read_bytes()


def archive_inventory(manifest_raw, archive_raw):
    manifest = json.loads(manifest_raw)
    assets = [item for item in manifest['assets'] if item['name'] == 'ultra-recovery.tar.gz']
    if len(assets) != 1 or len(archive_raw) != assets[0]['size'] or digest(archive_raw) != assets[0]['sha256']:
        raise ValueError('recovery_tools_archive_changed')
    members = {}; seen = set(); total = 0
    with tarfile.open(fileobj=io.BytesIO(archive_raw), mode='r:gz') as stream:
        for member in stream:
            if (not member.isfile() or not recovery_member_allowed(member.name)
                    or member.name in seen or len(seen) >= 64 or not 0 <= member.size <= 4 * 1024 * 1024):
                raise ValueError('recovery_tools_archive_unsafe')
            seen.add(member.name); total += member.size
            if total > 32 * 1024 * 1024:
                raise ValueError('recovery_tools_archive_unsafe')
            data = stream.extractfile(member).read(member.size + 1)
            if len(data) != member.size:
                raise ValueError('recovery_tools_archive_unsafe')
            if not member.name.startswith('test_'):
                members[member.name] = digest(data)
    required = ['recovery.py', 'db_connection.py', 'reconcile.py', 'monitor.py', 'heartbeat.py',
                'ultra-recovery-backup.service', 'ultra-recovery-backup.timer', 'ssh_policy.json']
    if any(name not in members for name in required):
        raise ValueError('recovery_tools_bundle_incomplete')
    return {'protocol': 'ultra-recovery-tools-v1', 'manifest_sha256': digest(manifest_raw), 'members': members}


def verify_dispatcher(manifest):
    if not CURRENT.is_symlink():
        raise ValueError('recovery_tools_dispatcher_unverified')
    directory = Path(os.readlink(CURRENT))
    if not re.fullmatch(r'/opt/ultra-ansible/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}', str(directory)):
        raise ValueError('recovery_tools_dispatcher_unverified')
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]
    assets = {item['name']: item for item in manifest['assets']}
    installer = assets['ultra-install-linux-' + arch]['sha256']
    runtime = assets['ultra-ansible-runtime-linux-' + arch + '.tar.gz']['sha256']
    if digest(regular(directory / 'ultra-install')) != installer or regular(directory / 'runtime.sha256', True).decode().strip() != runtime:
        raise ValueError('recovery_tools_dispatcher_unverified')
    sealed = json.loads(regular(RETENTION / (digest(str(directory).encode()) + '.json'), True, 4 * 1024 * 1024))
    if (sealed.get('schema') != 1 or sealed.get('path') != str(directory) or sealed.get('identity') != {
            'ultra-install': installer, 'runtime.sha256': digest((runtime + '\n').encode())}):
        raise ValueError('recovery_tools_runtime_unverified')
    inventory = {}
    for base, dirs, files in os.walk(directory, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(base) / name; info = path.lstat()
            if info.st_uid != os.geteuid() or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
                raise ValueError('recovery_tools_runtime_unverified')
            if name == '__pycache__' and stat.S_ISDIR(info.st_mode):
                continue
            if path.parent.name == '__pycache__' and stat.S_ISREG(info.st_mode):
                match = re.fullmatch(r'(.+)\.cpython-[0-9]+(?:\.opt-[0-9]+)?\.pyc', name)
                if match and (path.parent.parent / (match.group(1) + '.py')).is_file():
                    continue
            relative = str(path.relative_to(directory))
            if stat.S_ISLNK(info.st_mode):
                inventory[relative] = ['link', os.readlink(path)]
            elif stat.S_ISREG(info.st_mode):
                inventory[relative] = ['file', digest(regular(path)), stat.S_IMODE(info.st_mode)]
            elif stat.S_ISDIR(info.st_mode):
                inventory[relative] = ['directory', stat.S_IMODE(info.st_mode)]
            else:
                raise ValueError('recovery_tools_runtime_unverified')
            if len(inventory) > 30000:
                raise ValueError('recovery_tools_runtime_unverified')
    if inventory != sealed.get('inventory'):
        raise ValueError('recovery_tools_runtime_unverified')
    unit = SYSTEM / 'ultra-ansible-controller.service'
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(regular(unit).decode())
    expected = [str(directory / 'ultra-install'), 'ansible-controller', '--executable', str(directory / 'venv/bin/ansible-playbook')]
    if (shlex.split(parser['Service']['ExecStart']) != expected or parser['Service'].get('User') != 'root'
            or parser['Service'].get('Group') != 'root' or parser['Service'].get('KillMode') != 'control-group'):
        raise ValueError('recovery_tools_dispatcher_unverified')
    fields = dict(line.split('=',1) for line in subprocess.run([
        '/usr/bin/systemctl','show','--property=ActiveState,MainPID,ControlGroup,FragmentPath,KillMode,Delegate,User,Group',
        'ultra-ansible-controller.service'], check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5).stdout.decode().splitlines() if '=' in line)
    if (fields.get('ActiveState') != 'active' or fields.get('ControlGroup') != '/system.slice/ultra-ansible-controller.service'
            or fields.get('FragmentPath') != str(unit) or fields.get('KillMode') != 'control-group'
            or fields.get('Delegate') != 'no' or fields.get('User') != 'root' or fields.get('Group') != 'root'
            or not fields.get('MainPID','').isdigit() or int(fields['MainPID']) <= 1):
        raise ValueError('recovery_tools_dispatcher_unverified')
    proc = Path('/proc') / fields['MainPID']
    if (os.readlink(proc / 'exe') != str(directory / 'ultra-install')
            or digest((proc / 'exe').read_bytes()) != installer
            or (proc / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0') != [os.fsencode(value) for value in expected]
            or (proc / 'cgroup').read_bytes() != b'0::/system.slice/ultra-ansible-controller.service\n'):
        raise ValueError('recovery_tools_dispatcher_unverified')



def verify(dispatcher=True):
    manifest = regular(ROOT / NAMES[0], True, 1048576)
    archive = regular(ROOT / NAMES[1], True)
    inventory = archive_inventory(manifest, archive)
    if json.loads(regular(ROOT / NAMES[2], True, 1048576)) != inventory:
        raise ValueError('recovery_tools_inventory_changed')
    for name, checksum in inventory['members'].items():
        if digest(regular(ROOT / name)) != checksum:
            raise ValueError('recovery_tools_member_changed')
        if recovery_member_is_systemd_unit(name) and digest(regular(SYSTEM / name)) != checksum:
            raise ValueError('recovery_tools_member_changed')
    if dispatcher:
        verify_dispatcher(json.loads(manifest))
    return inventory


def identity_hashes():
    present = [os.path.lexists(ROOT / name) for name in NAMES]
    if not any(present):
        return {}
    if not all(present):
        raise ValueError('recovery_tools_identity_incomplete')
    verify(dispatcher=False)
    return {name: digest(regular(ROOT / name, True)) for name in NAMES}


if __name__ == '__main__':
    import sys
    if sys.argv[1:] != ['verify-staged']:
        raise SystemExit(2)
    verify(dispatcher=False)
