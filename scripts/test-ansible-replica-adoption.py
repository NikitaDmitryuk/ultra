#!/usr/bin/env python3
"""Read-only existing-standby adoption guards and transport-only play wiring."""
import importlib.util
import json
from pathlib import Path
import stat
from types import SimpleNamespace
from unittest.mock import patch

import yaml

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / 'deploy/ansible/library/ultra_replica_adoption_guard.py'
spec = importlib.util.spec_from_file_location('replica_adoption', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
SLOT = 'ultra_' + 'a' * 32
SYSTEM = '1234567890123456789'
PRIMARY = {'version': 16, 'recovery': False, 'system_id': SYSTEM, 'physical': True}
STANDBY = {'version': 16, 'recovery': True, 'data': module.DATA, 'slot': SLOT, 'system_id': SYSTEM, 'transport': True}


def rejected(call):
    try:
        call()
    except ValueError:
        return
    raise AssertionError('foreign or unavailable identity accepted')


def runner(value, policy=b'gatewayports no\n'):
    def run(argv, **kwargs):
        assert kwargs['stderr'] == module.subprocess.DEVNULL
        if argv[0] == '/usr/sbin/sshd':
            return SimpleNamespace(returncode=0, stdout=policy)
        assert argv[:5] == ['runuser', '-u', 'postgres', '--', 'psql']
        assert 'BEGIN READ ONLY;' in argv[-1]
        assert not any(word in argv[-1].lower() for word in ('insert ', 'update ', 'delete ', 'create ', 'alter '))
        assert kwargs['timeout'] <= 8
        return SimpleNamespace(returncode=0, stdout=json.dumps(value).encode())
    return run


assert module.primary(5432, SLOT, runner(PRIMARY)) == SYSTEM
for key, value in [('version', 15), ('recovery', True), ('physical', False), ('system_id', 'invalid')]:
    rejected(lambda: module.primary(5432, SLOT, runner(dict(PRIMARY, **{key: value}))))
for slot in ['foreign', SLOT + "'", 'ultra_' + 'A' * 32]:
    rejected(lambda: module.primary(5432, slot, runner(PRIMARY)))
rejected(lambda: module.primary(0, SLOT, runner(PRIMARY)))

inspected = []
def inspect(path, **kwargs):
    inspected.append((path, kwargs))

# Legacy existing streaming replica can lose transport when relay stops; the
# guard deliberately needs recovery/identity, not a currently connected receiver.
with patch.object(module.Path, 'read_text', return_value='16\n'):
    for _ in range(2):
        module.standby(SLOT, SYSTEM, runner(STANDBY), inspect)
    for key, value in [('version', 15), ('recovery', False), ('data', '/foreign'),
                       ('slot', 'foreign'), ('system_id', '999'), ('transport', False)]:
        rejected(lambda: module.standby(SLOT, SYSTEM, runner(dict(STANDBY, **{key: value})), inspect))
    rejected(lambda: module.standby(SLOT, SYSTEM, runner(STANDBY, b'gatewayports yes\n'), inspect))
    def foreign(*args, **kwargs):
        raise ValueError('foreign')
    rejected(lambda: module.standby(SLOT, SYSTEM, runner(STANDBY), foreign))
with patch.object(module.Path, 'read_text', return_value='15\n'):
    rejected(lambda: module.standby(SLOT, SYSTEM, runner(STANDBY), inspect))
assert any(path.endswith('managed-by-ultra') for path, _ in inspected)
assert any(path.endswith('standby.signal') for path, _ in inspected)

# Files, ancestors, ownership, and writable paths are independently enforced.
# The legacy marker is empty/root-owned; the new marker is text/postgres-owned.
for mode, uid, size in [(stat.S_IFREG | 0o644, 0, 0), (stat.S_IFREG | 0o600, 1001, 15)]:
    with patch.object(module.Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=uid, st_size=size)):
        module.owned('/fixture/marker', postgres_uid=1001)
for mode, uid in [(stat.S_IFLNK | 0o777, 0), (stat.S_IFREG | 0o666, 0), (stat.S_IFREG | 0o600, 1002)]:
    with patch.object(module.Path, 'lstat', return_value=SimpleNamespace(st_mode=mode, st_uid=uid, st_size=0)):
        rejected(lambda: module.owned('/fixture/marker', postgres_uid=1001))
with patch.object(module.Path, 'lstat', return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_size=0)):
    rejected(lambda: module.owned(module.DATA, directory=True, postgres_only=True, postgres_uid=1001))

play = yaml.safe_load((ROOT / 'deploy/ansible/playbooks/adopt-replica-tunnels.yml').read_text())
assert [item['hosts'] for item in play] == ['localhost', 'bridge', "{{ ultra_bootstrap_replica_host | default('__ultra_missing_replica_target__') }}", 'bridge']
assert all(item['any_errors_fatal'] for item in play)
assert 'ultra_bootstrap_replica_host is defined' in play[0]['tasks'][0]['ansible.builtin.assert']['that']
assert "groups.get('bridge', []) == ['bridge']" in play[0]['tasks'][0]['ansible.builtin.assert']['that']
assert 'replica_adoption_standby.verified' in str(play[-1]['pre_tasks'])
assert play[-1]['roles'] == ['replica_tunnel']
assert 'replica' not in play[-1]['roles']
role = yaml.safe_load((ROOT / 'deploy/ansible/roles/replica_tunnel/tasks/main.yml').read_text())
activate = next(item['ansible.builtin.systemd_service'] for item in role if 'ansible.builtin.systemd_service' in item)
assert activate['enabled'] is True
assert "else 'started'" in activate['state']
assert 'replica_tunnel_credentials.changed' in activate['state']
unit = (ROOT / 'deploy/ansible/roles/replica/templates/ultra-replica-tunnel.service.j2').read_text()
assert 'WantedBy=multi-user.target' in unit and 'Restart=on-failure' in unit
assert 'ultra-relay' not in unit
assert 'pg_basebackup' not in str(play) + str(role)
print('replica transport adoption checks passed')
