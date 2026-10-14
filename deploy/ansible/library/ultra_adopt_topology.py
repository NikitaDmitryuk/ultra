#!/usr/bin/python3
"""Bounded read-only adoption discovery; never provisions or mutates PostgreSQL."""
import hashlib
import ipaddress
import json
import os
import pwd
from pathlib import Path
import re
import stat
import subprocess
import uuid

QUERY = """BEGIN READ ONLY;
SET LOCAL statement_timeout='5s';
SELECT COALESCE(json_agg(row_to_json(t) ORDER BY t.id),'[]'::json) FROM (
SELECT n.id::text,n.name,n.address,n.port,n.tunnel_uuid,n.pinned_peer_cert_sha256,
n.priority,n.enabled,
(SELECT COALESCE(json_agg(json_build_object('id',c.id::text,'state',c.state,
'phase',c.body->>'phase','exit_id',c.body->>'exit_id','instance_id',c.body->>'instance_id')),'[]'::json)
FROM (SELECT id,state,body FROM cloud_operations WHERE body->>'exit_id'=n.id::text LIMIT 129) c) AS operations
FROM exit_nodes n WHERE n.enabled ORDER BY n.id LIMIT 17) t;
COMMIT;"""


def trusted_read(path, limit=65536, relay_prefix=None, relay_uid=None):
    path = Path(path)
    if not path.is_absolute() or any(part == '..' for part in path.parts):
        raise ValueError('adoption_topology_trust_unavailable')
    for parent in [path, *path.parents]:
        info = parent.lstat()
        relay_owned = relay_prefix is not None and (parent == relay_prefix or relay_prefix in parent.parents) and info.st_uid == relay_uid
        if stat.S_ISLNK(info.st_mode) or (info.st_uid != 0 and not relay_owned) or info.st_mode & 0o022:
            raise ValueError('adoption_topology_trust_unavailable')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        relay_owned = relay_prefix is not None and (path == relay_prefix or relay_prefix in path.parents) and info.st_uid == relay_uid
        if (info.st_uid != 0 and not relay_owned) or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= limit:
            raise ValueError('adoption_topology_trust_unavailable')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(limit + 1)
        if len(raw) > limit:
            raise ValueError('adoption_topology_trust_unavailable')
        return raw.decode('utf-8')
    finally:
        os.close(fd)


def topology(config, rows, read=trusted_read, check_pin=True):
    if not isinstance(rows, list) or not 0 < len(rows) <= 16:
        raise ValueError('adoption_topology_bounds')
    static = {}
    for node in config.get('static_nodes', []):
        address = str(ipaddress.ip_address(node['address']))
        if address in static or node.get('host', 'root@' + address) != 'root@' + address:
            raise ValueError('adoption_topology_static_conflict')
        static[address] = node
    seen = set()
    names = set()
    endpoints = set()
    identities = set()
    nodes = []
    for row in rows:
        identifier = str(uuid.UUID(row['id']))
        address = str(ipaddress.ip_address(row['address']))
        identity = str(uuid.UUID(row['tunnel_uuid']))
        name = row['name']
        port = row['port']
        pin = row['pinned_peer_cert_sha256']
        if row['enabled'] is not True or not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,95}', name):
            raise ValueError('adoption_topology_identity_invalid')
        if type(port) is not int or not 0 < port <= 65535 or type(row['priority']) is not int or row['priority'] <= 0 or not re.fullmatch(r'[0-9a-fA-F]{64}', pin):
            raise ValueError('adoption_topology_identity_invalid')
        if identifier in seen or name in names or (address, port) in endpoints or identity in identities:
            raise ValueError('adoption_topology_duplicate')
        seen.add(identifier)
        names.add(name)
        endpoints.add((address, port))
        identities.add(identity)
        operations = row['operations']
        if not isinstance(operations, list) or len(operations) > 128:
            raise ValueError('adoption_topology_bounds')
        if address in static:
            if operations:
                raise ValueError('adoption_topology_static_conflict')
            source = static[address]['known_hosts']
        else:
            if len(operations) != 1:
                raise ValueError('adoption_topology_managed_identity_invalid')
            operation = operations[0]
            if operation['id'] != identifier or operation['exit_id'] != identifier or operation['state'] != 'ready' or operation['phase'] != 'ready' or not operation['instance_id']:
                raise ValueError('adoption_topology_managed_identity_invalid')
            if config['vultr_state_dir'] != '/var/lib/ultra-relay/vultr':
                raise ValueError('adoption_topology_managed_trust_invalid')
            source = str(Path(config['vultr_state_dir']) / identifier / 'known_hosts')
        if read is trusted_read and address not in static:
            pins = trusted_read(source, relay_prefix=Path('/var/lib/ultra-relay'), relay_uid=pwd.getpwnam('ultra-relay').pw_uid)
        else:
            pins = read(source)
        if len(pins.encode()) > 65536:
            raise ValueError('adoption_topology_bounds')
        if check_pin:
            result = subprocess.run(['ssh-keygen', '-F', address, '-f', source], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5)
            if result.returncode:
                raise ValueError('adoption_topology_pins_unavailable')
        nodes.append({'id': identifier, 'name': name, 'address': address, 'port': port,
                      'tunnel_uuid': identity, 'pinned_peer_cert_sha256': pin.lower(),
                      'priority': row['priority'], 'enabled': True, 'pins': pins})
    nodes.sort(key=lambda node: node['id'])
    digest = hashlib.sha256(json.dumps(nodes, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    return {'nodes': nodes, 'sha256': digest}


def probe(database, expected=''):
    config = json.loads(trusted_read('/etc/ultra-recovery/reconcile.json', 1048576))
    if not re.fullmatch(r'[A-Za-z0-9_-]+', database) or config['database'] != database:
        raise ValueError('adoption_topology_database_conflict')
    result = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', database, '-c', QUERY], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=8)
    if result.returncode or len(result.stdout) > 1048576:
        raise ValueError('adoption_topology_unavailable')
    value = topology(config, json.loads(result.stdout))
    if expected and expected != value['sha256']:
        raise ValueError('adoption_topology_changed')
    return value


def certificate_pin():
    pem = trusted_read('/etc/ultra-relay/fullchain.pem', relay_prefix=Path('/etc/ultra-relay'),
                       relay_uid=pwd.getpwnam('ultra-relay').pw_uid)
    result = subprocess.run(['openssl', 'x509', '-outform', 'DER'], input=pem.encode(),
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
    if result.returncode or not 0 < len(result.stdout) <= 65536:
        raise ValueError('adoption_topology_certificate_unavailable')
    return hashlib.sha256(result.stdout).hexdigest()


def main():
    from ansible.module_utils.basic import AnsibleModule
    module = AnsibleModule(argument_spec={'database': {'type': 'str', 'default': ''}, 'certificate': {'type': 'bool', 'default': False}, 'expected': {'type': 'str', 'default': ''}}, supports_check_mode=True)
    try:
        if module.params['certificate']:
            module.exit_json(changed=False, certificate_pin=certificate_pin())
        module.exit_json(changed=False, topology=probe(module.params['database'], module.params['expected']))
    except Exception:
        module.fail_json(msg='adoption_topology_unavailable_or_changed')


if __name__ == '__main__':
    main()
