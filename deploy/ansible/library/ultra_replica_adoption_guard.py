#!/usr/bin/python3
"""Read-only identity checks for adopting existing managed replica transport."""
import ipaddress
import json
from pathlib import Path
import pwd
import re
import stat
import subprocess

DATA = '/var/lib/ultra-postgres-replica/data'


def query(port, sql, runner=subprocess.run):
    if type(port) is not int or not 0 < port <= 65535:
        raise ValueError('replica_adoption_port_invalid')
    result = runner(['runuser', '-u', 'postgres', '--', 'psql', '-p', str(port),
                     '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', 'postgres', '-c',
                     "BEGIN READ ONLY; SET LOCAL statement_timeout='5s'; " + sql + '; COMMIT;'],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
    if result.returncode or len(result.stdout) > 65536:
        raise ValueError('replica_adoption_database_unavailable')
    return json.loads(result.stdout)


def valid_slot(slot):
    if not isinstance(slot, str) or not re.fullmatch(r'ultra_[a-f0-9]{32}', slot):
        raise ValueError('replica_adoption_slot_invalid')


def primary(port, slot, runner=subprocess.run):
    valid_slot(slot)
    value = query(port, "SELECT json_build_object('version',current_setting('server_version_num')::int/10000,"
                  "'recovery',pg_is_in_recovery(),'system_id',(SELECT system_identifier::text FROM pg_control_system()),"
                  "'physical',EXISTS(SELECT 1 FROM pg_replication_slots WHERE slot_name='" + slot + "' AND slot_type='physical'))", runner)
    if (value['version'] != 16 or value['recovery'] is not False or value['physical'] is not True
            or not re.fullmatch(r'[0-9]{1,20}', value['system_id'])):
        raise ValueError('replica_adoption_primary_identity_invalid')
    return value['system_id']


def owned(path, directory=False, postgres_only=False, postgres_uid=None):
    # Check ancestors as well: lstat on a file alone follows a symlinked parent.
    uid = pwd.getpwnam('postgres').pw_uid if postgres_uid is None else postgres_uid
    candidate = Path(path)
    for parent in [candidate, *candidate.parents]:
        info = parent.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid not in (0, uid) or info.st_mode & 0o022:
            raise ValueError('replica_adoption_foreign_data')
    info = candidate.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(info.st_mode) or (postgres_only and info.st_uid != uid):
        raise ValueError('replica_adoption_foreign_data')
    if not directory and info.st_size > 65536:
        raise ValueError('replica_adoption_foreign_data')


def standby(slot, system_id, runner=subprocess.run, inspect=owned):
    valid_slot(slot)
    if not isinstance(system_id, str) or not re.fullmatch(r'[0-9]{1,20}', system_id):
        raise ValueError('replica_adoption_primary_identity_invalid')
    inspect('/var/lib/ultra-postgres-replica', directory=True)
    inspect(DATA, directory=True, postgres_only=True)
    inspect('/var/lib/ultra-postgres-replica/managed-by-ultra')
    inspect(DATA + '/standby.signal')
    inspect(DATA + '/PG_VERSION', postgres_only=True)
    if Path(DATA + '/PG_VERSION').read_text().strip() != '16':
        raise ValueError('replica_adoption_version_invalid')
    # Never return primary_conninfo: it can contain credentials. Only test the
    # expected loopback destination/application identity inside PostgreSQL.
    value = query(5433, "SELECT json_build_object('version',current_setting('server_version_num')::int/10000,"
                  "'recovery',pg_is_in_recovery(),'data',current_setting('data_directory'),"
                  "'slot',current_setting('primary_slot_name'),'system_id',(SELECT system_identifier::text FROM pg_control_system()),"
                  "'transport',current_setting('primary_conninfo') ~ '(^| )host=127[.]0[.]0[.]1( |$)' "
                  "AND current_setting('primary_conninfo') ~ '(^| )port=15432( |$)' "
                  "AND current_setting('primary_conninfo') ~ '(^| )application_name=" + slot + "( |$)')", runner)
    if value != {'version': 16, 'recovery': True, 'data': DATA, 'slot': slot, 'system_id': system_id, 'transport': True}:
        raise ValueError('replica_adoption_standby_identity_invalid')
    policy = runner(['/usr/sbin/sshd', '-T'], stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL, timeout=5)
    if policy.returncode or not any(line in (b'gatewayports no', b'gatewayports clientspecified') for line in policy.stdout.splitlines()):
        raise ValueError('replica_adoption_gateway_policy_invalid')


def main():
    from ansible.module_utils.basic import AnsibleModule
    module = AnsibleModule(argument_spec={
        'action': {'type': 'str', 'required': True, 'choices': ['primary', 'standby']},
        'slot': {'type': 'str', 'required': True},
        'port': {'type': 'int', 'default': 5432},
        'system_id': {'type': 'str', 'default': ''},
        'address': {'type': 'str', 'default': ''},
    }, supports_check_mode=True)
    try:
        if module.params['action'] == 'primary':
            system_id = primary(module.params['port'], module.params['slot'])
            module.exit_json(changed=False, system_id=system_id)
        else:
            ipaddress.ip_address(module.params['address'])
            standby(module.params['slot'], module.params['system_id'])
            module.exit_json(changed=False, verified=True)
    except Exception:
        module.fail_json(msg='replica_adoption_identity_unavailable_or_changed')


if __name__ == '__main__':
    main()
