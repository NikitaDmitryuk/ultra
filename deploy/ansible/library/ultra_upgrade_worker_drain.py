#!/usr/bin/python
"""Read-only, fail-closed census before an abandoned upgrade is superseded."""
import configparser
import hashlib
import json
import os
import re
import shlex
from pathlib import Path
import uuid

from ansible.module_utils.basic import AnsibleModule


def private(path):
    info = path.lstat()
    if path.is_symlink() or not path.is_file() or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_size > 1048576:
        raise ValueError('worker_drain_evidence_invalid')
    return path.read_bytes()


def option(argv, key):
    indexes = [index for index, value in enumerate(argv) if value == key]
    if len(indexes) != 1 or indexes[0] + 1 >= len(argv):
        raise ValueError('worker_drain_controller_invalid')
    return os.fsdecode(argv[indexes[0] + 1])


def playbook_argv(argv):
    """Recognize only the executable position, including Linux shebang argv."""
    if argv and argv[0].rsplit(b'/', 1)[-1] == b'ansible-playbook':
        return argv
    if (len(argv) > 1 and re.fullmatch(rb'python(?:3(?:\.[0-9]+)?)?', argv[0].rsplit(b'/', 1)[-1])
            and argv[1].rsplit(b'/', 1)[-1] == b'ansible-playbook'):
        return argv[1:]
    return None


def broker_identity(pid, argv, metadata, run_command,
                    unit_path=Path('/etc/systemd/system/ultra-ansible-controller.service')):
    """A broker is exempt only as the exact root systemd main process."""
    fail = 'worker_drain_broker_unverified'
    if (len(argv) != 4 or not re.fullmatch(rb'/opt/ultra-ansible/releases/[A-Za-z0-9][A-Za-z0-9._-]{0,95}/ultra-install', argv[0])
            or argv[1:3] != [b'ansible-controller', b'--executable']
            or argv[3] != argv[0].rsplit(b'/', 1)[0] + b'/venv/bin/ansible-playbook'
            or metadata['uid'] != 0 or metadata['parent'] != 1):
        raise ValueError(fail)
    properties = ['Id', 'MainPID', 'ControlGroup', 'User', 'Group', 'ActiveState', 'SubState', 'FragmentPath', 'DropInPaths']
    code, output, _ = run_command(['systemctl', 'show'] + ['--property=' + key for key in properties]
                                  + ['--', 'ultra-ansible-controller.service'])
    if code or len(output) > 65536:
        raise ValueError(fail)
    rows = [line.split('=', 1) for line in output.splitlines()]
    if any(len(row) != 2 for row in rows) or len(rows) != len(properties) or len(dict(rows)) != len(rows):
        raise ValueError(fail)
    values = dict(rows)
    expected = {'Id': 'ultra-ansible-controller.service', 'MainPID': str(pid),
                'ControlGroup': '/system.slice/ultra-ansible-controller.service', 'User': 'root', 'Group': 'root',
                'ActiveState': 'active', 'SubState': 'running', 'FragmentPath': str(unit_path), 'DropInPaths': ''}
    if values != expected or metadata.get('cgroup') != b'0::' + expected['ControlGroup'].encode() + b'\n':
        raise ValueError(fail)
    info = unit_path.lstat()
    if unit_path.is_symlink() or not unit_path.is_file() or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 65536:
        raise ValueError(fail)
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(unit_path.read_text())
        service = parser['Service']
        command = [os.fsencode(value) for value in shlex.split(service['ExecStart'])]
        if (command != argv or service['User'] != 'root' or service['Group'] != 'root'
                or service['KillMode'] != 'control-group' or service.get('ExecStartPre') or service.get('ExecStartPost')):
            raise ValueError(fail)
    except (configparser.Error, KeyError):
        raise ValueError(fail) from None
    # This process is the broker, not a playbook worker. service.go's dispatch
    # loop calls gate.jobLock before Execute: applying rejects all queued jobs.
    # The caller holds the old applying lease/OFD through this census and atomic
    # supersession, so a broker restart also cannot acquire an independent lock.
    return True


def controller(argv, old_id, new_id):
    argv = playbook_argv(argv)
    if argv is None:
        raise ValueError('worker_drain_controller_invalid')
    directory = Path(option(argv, b'-i')).parent
    root = directory.parent
    if not directory.is_absolute() or directory.resolve() != directory or not directory.name.startswith('handoff-drain-'):
        raise ValueError('worker_drain_controller_invalid')
    for path in (directory, root):
        info = path.lstat()
        if path.is_symlink() or not path.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('worker_drain_evidence_invalid')
    if str(uuid.UUID(bytes=hashlib.sha256(str(root).encode()).digest()[:16], version=4)) != new_id:
        raise ValueError('worker_drain_controller_invalid')
    raw = private(directory / 'request.json')
    request = json.loads(raw)
    job = json.loads(private(directory / 'job.json'))
    receipt = json.loads(private(directory / 'receipt.json'))
    digest = hashlib.sha256(raw).hexdigest()
    for evidence in (job, receipt):
        if (evidence.get('schema_version') != 1 or evidence.get('operation') != 'drain-upgrade-workers'
                or evidence.get('request_sha256') != digest):
            raise ValueError('worker_drain_controller_invalid')
    if (receipt.get('state') != 'running' or receipt.get('binary_sha256') != job.get('binary_sha256')
            or type(receipt.get('started_at')) is not int
            or request['variables'].get('ultra_forward_old_id') != old_id
            or request['variables'].get('ultra_lifecycle_id') != new_id):
        raise ValueError('worker_drain_controller_invalid')
    expected = [argv[0], b'-i', os.fsencode(directory / 'inventory.yml'),
                os.fsencode(directory / 'bundle/playbooks/drain-upgrade-workers.yml'),
                b'--extra-vars', b'@' + os.fsencode(directory / 'variables.yml')]
    if argv != expected:
        raise ValueError('worker_drain_controller_invalid')
    return directory, receipt['started_at']


def allowances(processes, metadata, own, old_id, new_id, local, verify_broker=None):
    bound = {}
    brokers = set()
    for pid, argv in processes.items():
        if len(argv) > 1 and argv[0].rsplit(b'/', 1)[-1].startswith(b'ultra-install') and argv[1] == b'ansible-controller':
            if not local or verify_broker is None or not verify_broker(pid, argv, metadata[pid]):
                raise ValueError('worker_drain_broker_unverified')
            brokers.add(pid)
        if playbook_argv(argv) is not None:
            if not local:
                raise ValueError('worker_drain_foreign_controller')
            directory, _ = controller(argv, old_id, new_id)
            if metadata[pid]['uid'] != 0:
                raise ValueError('worker_drain_controller_unprivileged')
            bound[pid] = directory
    allowed = {own}
    if not local:
        # SSH and become wrappers for this exact module may still retain its
        # command string. Exempt only its shell ancestors, never an installer.
        current = metadata.get(own, {}).get('parent')
        seen = set()
        while current in metadata and current not in seen:
            seen.add(current)
            argv = processes[current]
            if not argv or argv[0].rsplit(b'/', 1)[-1] not in (b'sh', b'bash', b'dash', b'sudo', b'sshd'):
                break
            allowed.add(current)
            current = metadata[current]['parent']
        return allowed
    if len(brokers) != 1:
        raise ValueError('worker_drain_broker_unverified')
    allowed.update(brokers)
    roots = [pid for pid in bound if metadata[pid]['parent'] not in bound]
    if len(roots) != 1 or len(set(bound.values())) != 1:
        raise ValueError('worker_drain_ambiguous_controller')
    allowed.update(bound)
    current = metadata[roots[0]]['parent']
    seen = set()
    installers = []
    while current in metadata and current not in seen:
        seen.add(current)
        argv = processes[current]
        if argv and argv[0].rsplit(b'/', 1)[-1].startswith(b'ultra-install'):
            if (metadata[current]['uid'] != 0 or b'operator-upgrade' not in argv or b'--forward-only' not in argv
                    or Path(option(argv, b'--job-dir')) != bound[roots[0]].parent):
                raise ValueError('worker_drain_operator_invalid')
            installers.append(current)
            allowed.add(current)
        current = metadata[current]['parent']
    if len(installers) != 1:
        raise ValueError('worker_drain_operator_invalid')
    # Prove this invocation is under that one controller; no independently
    # surviving module gets a name-based exemption.
    current = own
    seen = set()
    while current in metadata and current not in seen and current not in bound:
        seen.add(current)
        current = metadata[current]['parent']
    if current not in bound:
        raise ValueError('worker_drain_module_unbound')
    allowed.update(seen)
    return allowed


def validate_processes(processes, allowed):
    for pid, argv in processes.items():
        if pid in allowed:
            continue
        if playbook_argv(argv) is not None:
            raise ValueError('worker_drain_legacy_worker_live')
        for value in argv:
            name = value.rsplit(b'/', 1)[-1]
            if (name.startswith(b'ultra-install') or b'AnsiballZ_' in value
                    or b'/ansible-tmp-' in value):
                raise ValueError('worker_drain_legacy_worker_live')


def census(old_id, new_id, local, root=Path('/proc'), own=None, run_command=None):
    own = os.getpid() if own is None else own
    processes, metadata = {}, {}
    scanned = 0
    for entry in root.iterdir():
        if not entry.name.isdigit():
            continue
        scanned += 1
        if scanned > 16384:
            raise ValueError('worker_drain_census_overflow')
        try:
            before = (entry / 'stat').read_bytes()
            with (entry / 'cmdline').open('rb') as source:
                argv = source.read(65537)
            cgroup = (entry / 'cgroup').read_bytes()
            after = (entry / 'stat').read_bytes()
            uid = entry.stat().st_uid
        except FileNotFoundError:
            continue
        if len(before) > 4096 or len(after) > 4096 or len(argv) > 65536 or len(cgroup) > 65536:
            raise ValueError('worker_drain_process_invalid')
        fields, previous = after.rsplit(b')', 1)[1].split(), before.rsplit(b')', 1)[1].split()
        if fields[19] != previous[19] or fields[1] != previous[1]:
            raise ValueError('worker_drain_process_changed')
        pid = int(entry.name)
        processes[pid] = argv.rstrip(b'\0').split(b'\0')
        metadata[pid] = {'parent': int(fields[1]), 'start': int(fields[19]), 'uid': uid, 'cgroup': cgroup}
    # Parent/start snapshots reject PID reuse. One connected controller tree
    # under the unique current operator proves identity without second-granular
    # receipt timestamps, which cannot distinguish same-second stale workers.
    allowed = allowances(processes, metadata, own, old_id, new_id, local,
        lambda pid, argv, info: broker_identity(pid, argv, info, run_command))
    validate_processes(processes, allowed)


def main():
    module = AnsibleModule(argument_spec={'old_id': {'type': 'str', 'required': True},
        'new_id': {'type': 'str', 'required': True}, 'local_controller': {'type': 'bool', 'default': False}}, supports_check_mode=True)
    try:
        if os.geteuid() != 0:
            raise ValueError('worker_drain_requires_root')
        for name in ('old_id', 'new_id'):
            if str(uuid.UUID(module.params[name])) != module.params[name]:
                raise ValueError('worker_drain_identity_invalid')
        if module.params['old_id'] == module.params['new_id']:
            raise ValueError('worker_drain_identity_invalid')
        census(module.params['old_id'], module.params['new_id'], module.params['local_controller'], run_command=module.run_command)
        module.exit_json(changed=False, verified=True)
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        module.fail_json(msg='upgrade_forward_workers_not_drained')


if __name__ == '__main__':
    main()
