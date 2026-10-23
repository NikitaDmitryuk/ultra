"""Attest the real systemd owner before a production mutator dispatches."""
import hashlib
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess


def manager_command(*arguments):
    environment = {'PATH': '/usr/bin:/bin'}
    prefix = ['/usr/bin/systemctl']
    if os.geteuid() != 0:
        runtime = '/run/user/' + str(os.geteuid())
        trusted(runtime, directory=True)
        environment['XDG_RUNTIME_DIR'] = runtime
        prefix.append('--user')
    return subprocess.run([*prefix, *arguments], env=environment,
                          capture_output=True, text=True, check=True, timeout=10)


def trusted(path, directory=False):
    path = Path(path)
    for member in [path, *path.parents]:
        info = member.lstat()
        if info.st_uid not in (0, os.geteuid()) or info.st_mode & 0o022 or stat.S_ISLNK(info.st_mode):
            raise ValueError('execution_containment_unverified')
        if member == path and not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)):
            raise ValueError('execution_containment_unverified')
    return path


def require_containment(directory, generation):
    fail = ValueError('execution_containment_unverified')
    groups = [line.split(':', 2)[2] for line in Path('/proc/self/cgroup').read_text().splitlines()
              if line.startswith('0::')]
    if len(groups) != 1:
        raise fail
    group = groups[0]
    if os.geteuid() == 0:
        expression = r'/system.slice/(ultra-(?:execution-[a-f0-9]{32}|ansible-controller|recovery-reconcile)\.service)'
        fragment_prefixes = ('/etc/systemd/system/', '/run/systemd/transient/')
        users = ('', 'root')
    else:
        uid = str(os.geteuid())
        prefix = '/user.slice/user-' + uid + '.slice/user@' + uid + '.service/app.slice/'
        expression = re.escape(prefix) + r'(ultra-execution-[a-f0-9]{32}\.service)'
        fragment_prefixes = ('/run/user/' + uid + '/systemd/transient/',)
        users = ('', uid, pwd.getpwuid(os.geteuid()).pw_name)
        expected_state = Path(pwd.getpwuid(os.geteuid()).pw_dir) / '.local/state/ultra-ansible'
        if os.environ.get('ULTRA_OPERATOR_STATE_DIRECTORY') != str(expected_state):
            raise fail
        trusted(expected_state, directory=True)
    match = re.fullmatch(expression, group)
    if not match:
        raise fail
    unit = match[1]
    names = ('LoadState', 'ActiveState', 'ControlGroup', 'KillMode', 'Delegate', 'User', 'MainPID', 'FragmentPath', 'ExecStart')
    result = manager_command('show', unit, '--no-pager', *['--property=' + name for name in names])
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    if (values.get('LoadState') != 'loaded' or values.get('ActiveState') not in ('active', 'activating')
            or values.get('ControlGroup') != group or values.get('KillMode') != 'control-group'
            or values.get('Delegate') != 'no' or values.get('User') not in users):
        raise fail
    fragment = values.get('FragmentPath', '')
    if not any(fragment.startswith(prefix) for prefix in fragment_prefixes):
        raise fail
    trusted(fragment)
    pid = int(values.get('MainPID', '0'))
    if pid <= 0:
        raise fail
    process = Path('/proc') / str(pid)
    if not any(line == '0::' + group for line in (process / 'cgroup').read_text().splitlines()):
        raise fail
    uid = next(line.split()[1:] for line in (process / 'status').read_text().splitlines() if line.startswith('Uid:'))
    if uid != [str(os.geteuid())] * 4:
        raise fail
    argv = [os.fsdecode(value) for value in (process / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0')]
    executable = (process / 'exe').resolve(strict=True)
    trusted(executable)
    if not argv or not os.path.samefile(argv[0], executable):
        raise fail
    start = re.match(r'^\{ path=([^ ;]+) ;', values.get('ExecStart', ''))
    if not start or not os.path.samefile(start[1], executable):
        raise fail
    if unit.startswith('ultra-execution-'):
        expected = 'ultra-execution-' + str(generation) + '.service'
        if (unit != expected or pid != os.getpid() or len(argv) != 8
                or argv[1:] != [str(Path(directory) / 'bundle/controller.py'), '--job', str(directory),
                                '--bundle', str(Path(directory) / 'bundle'), '--executable', argv[-1]]):
            raise fail
    elif unit == 'ultra-ansible-controller.service':
        if (not re.fullmatch(r'/opt/ultra-ansible/releases/[A-Za-z0-9._-]+/ultra-install', str(executable))
                or argv[1:] != ['ansible-controller', '--executable', str(executable.parent / 'venv/bin/ansible-playbook')]):
            raise fail
    elif unit == 'ultra-recovery-reconcile.service':
        if argv[1:] != ['/opt/ultra-recovery/reconcile.py', '--config', '/etc/ultra-recovery/reconcile.json']:
            raise fail
        trusted('/opt/ultra-recovery/reconcile.py')
    return unit


def process_identity(pid):
    """Identity is stable across PID reuse, executable changes and reparenting."""
    process = Path('/proc') / str(pid)
    fields = (process / 'stat').read_text().rsplit(')', 1)[1].split()
    uid = next(line.split()[1:] for line in (process / 'status').read_text().splitlines() if line.startswith('Uid:'))
    if uid != [str(os.geteuid())] * 4:
        raise ValueError('execution_containment_unverified')
    groups = (process / 'cgroup').read_text().splitlines()
    group = next(line[3:] for line in groups if line.startswith('0::'))
    executable = (process / 'exe').resolve(strict=True)
    trusted(executable)
    return {'pid': pid, 'parent': int(fields[1]), 'starttime': fields[19], 'group': group,
            'executable_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
            'argv_sha256': hashlib.sha256((process / 'cmdline').read_bytes()).hexdigest()}


def cgroup_processes(group):
    root = Path('/sys/fs/cgroup') / group.lstrip('/')
    processes = set()
    # Include descendant cgroups, even though Delegate=no prevents untrusted delegation.
    for path in [root / 'cgroup.procs', *root.glob('**/cgroup.procs')]:
        processes.update(int(value) for value in path.read_text().split())
    return processes


def completion_containment(directory, fence):
    unit = require_containment(directory, fence['generation'])
    result = manager_command('show', unit, '--property=MainPID', '--property=InvocationID', '--property=ControlGroup')
    values = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    owner = int(values['MainPID'])
    invocation = values.get('InvocationID', '')
    if not re.fullmatch('[a-f0-9]{32}', invocation):
        raise ValueError('execution_containment_unverified')
    chain = []
    pid = os.getpid()
    while True:
        if pid <= 0 or len(chain) >= 64 or any(member['pid'] == pid for member in chain):
            raise ValueError('execution_containment_unverified')
        member = process_identity(pid)
        if member['group'] != values.get('ControlGroup'):
            raise ValueError('execution_containment_unverified')
        chain.append(member)
        if pid == owner:
            break
        pid = member['parent']
    allowed = {member['pid'] for member in chain}
    for _ in range(2):
        if cgroup_processes(chain[0]['group']) != allowed:
            raise ValueError('execution_containment_workers_live')
        if any(process_identity(member['pid']) != member for member in chain):
            raise ValueError('execution_containment_unverified')
    proof = {'schema': 1, 'fence': fence, 'unit': unit, 'invocation_id': invocation,
             'mode': 'reuse' if not unit.startswith('ultra-execution-') else 'transient',
             'chain': chain}
    if os.geteuid() != 0:
        proof.update(schema=2, manager='user', uid=os.geteuid(), control_group=values['ControlGroup'])
    return proof
