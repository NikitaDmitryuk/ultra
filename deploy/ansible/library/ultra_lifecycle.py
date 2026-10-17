#!/usr/bin/python
"""Fixed root-only bridge lifecycle reservation; no user-controlled commands."""
from ansible.module_utils.basic import AnsibleModule
import os
import stat
import re
import json
import ipaddress
import shlex
import time
import urllib.request
from pathlib import Path


LIFECYCLE_LOCK_RETRY_SECONDS = 120
LIFECYCLE_LOCK_RETRY_INTERVAL = 1
INFRASTRUCTURE_BUSY = re.compile(r'(?:^|\n)Ansible lease: infrastructure_busy(?: \([^()\r\n]*\))?(?:\r?\n|$)')


def run_lifecycle_transition(run_command, phase, sleep=time.sleep, monotonic=time.monotonic,
                             retry_seconds=LIFECYCLE_LOCK_RETRY_SECONDS):
    """Retry only an applying reservation rejected by the shared infrastructure lock."""
    deadline = monotonic() + retry_seconds
    while True:
        code, stdout, stderr = run_command()
        if code == 0:
            return True
        output = (stdout or '') + '\n' + (stderr or '')
        if phase != 'applying' or not INFRASTRUCTURE_BUSY.search(output):
            return False
        remaining = deadline - monotonic()
        if remaining <= 0:
            return None
        sleep(min(LIFECYCLE_LOCK_RETRY_INTERVAL, remaining))


def main():
    module = AnsibleModule(argument_spec={
        'id': {'type': 'str', 'required': True},
        'drain': {'type': 'bool', 'default': True},
        'reserve_only': {'type': 'bool', 'default': False},
        'resume_frozen': {'type': 'bool', 'default': False},
        'phase': {'type': 'str', 'required': True, 'choices': ['applying', 'checking', 'released']},
    }, supports_check_mode=True)
    if not re.fullmatch(r'[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}', module.params['id']):
        module.fail_json(msg='invalid_operation_id')
    if os.geteuid() != 0:
        module.fail_json(msg='root_operator_required')
    if module.check_mode:
        module.exit_json(changed=False)
    command = [
        '/opt/ultra-ansible/current/ultra-install', 'ansible-lease', '--id', module.params['id'],
        '--phase', module.params['phase'],
    ]
    if module.params['resume_frozen']:
        if module.params['phase'] != 'applying':
            module.fail_json(msg='invalid_resume_phase')
        command.append('--resume-frozen')
    result = run_lifecycle_transition(lambda: module.run_command(command), module.params['phase'])
    if result is not True:
        module.fail_json(msg='lifecycle_infrastructure_busy' if result is None else 'lifecycle_transition_failed')
    try:
        journal = Path('/var/lib/ultra-ansible/lifecycle.json')
        metadata = journal.lstat()
        if journal.is_symlink() or not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096 or metadata.st_uid != 0 or metadata.st_mode & 0o077:
            raise ValueError('invalid_reservation')
        if json.loads(journal.read_text()) != {'id': module.params['id'], 'phase': module.params['phase']}:
            raise ValueError('invalid_reservation')
    except (OSError, ValueError):
        module.fail_json(msg='lifecycle_reservation_unverified')
    if module.params['reserve_only']:
        if module.params['phase'] != 'applying' or module.params['drain'] or module.params['resume_frozen']:
            module.fail_json(msg='lifecycle_invalid_reservation_only')
        module.exit_json(changed=False, verified=True, reservation_id=module.params['id'], reservation_phase='applying')
    if module.params['phase'] == 'applying' and not module.params['drain'] and not module.params['resume_frozen']:
        # Suppressing drain is allowed only with a positively absent/stopped
        # worker. An old checkpoint alone cannot prove it after a partial apply.
        active, _, _ = module.run_command(['systemctl', 'is-active', 'ultra-relay.service'])
        if active not in (3, 4):
            module.fail_json(msg='lifecycle_undrained_worker_running')
        if active == 3:
            code, main_pid, _ = module.run_command(['systemctl', 'show', '-p', 'MainPID', '--value', 'ultra-relay.service'])
            if code or main_pid.strip() != '0':
                module.fail_json(msg='lifecycle_undrained_worker_running')

    if module.params['phase'] == 'applying' and module.params['drain']:
        try:
            spec = json.loads(Path('/etc/ultra-relay/spec.json').read_text())
            address = spec['admin_listen']
            host, port = address.rsplit(':', 1)
            if not ipaddress.ip_address(host.strip('[]')).is_loopback or not 1 <= int(port) <= 65535:
                raise ValueError('invalid_admin_address')
            values = {}
            for line in Path('/etc/ultra-relay/environment').read_text().splitlines():
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    parsed = shlex.split(value)
                    if len(parsed) == 1:
                        values[key] = parsed[0]
            request = urllib.request.Request('http://' + address + '/v1/deployment/drain', data=b'',
                                             headers={'Authorization': 'Bearer ' + values['ULTRA_RELAY_ADMIN_TOKEN']})
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(request, timeout=20) as response:
                if json.load(response).get('verified') is not True:
                    raise ValueError('drain_not_verified')
        except (OSError, ValueError, KeyError):
            # A failed drain intentionally retains the lease: retry this operation
            # before inspection; do not reopen topology on an ambiguous failure.
            module.fail_json(msg='lifecycle_drain_failed')
    # Transition is idempotent; fixed command doesn't expose private state.
    module.exit_json(changed=False, verified=True, reservation_id=module.params['id'], reservation_phase=module.params['phase'])


if __name__ == '__main__':
    main()
