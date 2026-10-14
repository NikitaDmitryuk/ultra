#!/usr/bin/python
"""Observe recovery workers without interrupting their running generation."""
from ansible.module_utils.basic import AnsibleModule
import re

SERVICES = ['ultra-recovery-backup.service', 'ultra-recovery-reconcile.service']
PROPERTIES = ['LoadState', 'ActiveState', 'MainPID', 'ControlPID']


def idle_status(output):
    values = {}
    for line in output.splitlines():
        key, separator, value = line.partition('=')
        if not separator or key not in PROPERTIES or key in values:
            raise ValueError('recovery_worker_state_invalid')
        values[key] = value
    if set(values) != set(PROPERTIES):
        raise ValueError('recovery_worker_state_invalid')
    if values['LoadState'] not in ('loaded', 'not-found'):
        raise ValueError('recovery_worker_load_state_invalid')
    if values['ActiveState'] not in ('active', 'activating', 'deactivating', 'reloading', 'inactive', 'failed'):
        raise ValueError('recovery_worker_active_state_invalid')
    if any(not re.fullmatch(r'[0-9]+', values[key]) for key in ('MainPID', 'ControlPID')):
        raise ValueError('recovery_worker_pid_invalid')
    no_processes = values['MainPID'] == '0' and values['ControlPID'] == '0'
    if values['LoadState'] == 'not-found':
        if values['ActiveState'] != 'inactive' or not no_processes:
            raise ValueError('recovery_worker_missing_state_invalid')
        return True
    return values['ActiveState'] in ('inactive', 'failed') and no_processes


def main():
    module = AnsibleModule(argument_spec={
        'service': {'type': 'str', 'required': True, 'choices': SERVICES},
    }, supports_check_mode=True)
    rc, output, _ = module.run_command(
        ['systemctl', 'show'] + ['--property=' + key for key in PROPERTIES] + [module.params['service']])
    if rc != 0:
        module.fail_json(msg='recovery_worker_state_unavailable')
    try:
        idle = idle_status(output)
    except ValueError as error:
        module.fail_json(msg=str(error))
    module.exit_json(changed=False, idle=idle)


if __name__ == '__main__':
    main()
