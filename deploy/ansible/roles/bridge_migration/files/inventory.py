#!/usr/bin/python3
"""Read-only migration sizing/identity; private service values never leave host."""
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys


def main():
    action = sys.argv[1]
    operating = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        key, _, value = line.partition('=')
        operating[key] = value.strip('"')
    result = {'machine_id': Path('/etc/machine-id').read_text().strip(), 'architecture': platform.machine(),
              'os': operating.get('ID'), 'os_version': operating.get('VERSION_ID'), 'python_abi': '.'.join(str(v) for v in sys.version_info[:2]), 'cpu_count': os.cpu_count(), 'memory_bytes': int(Path('/proc/meminfo').read_text().splitlines()[0].split()[1]) * 1024,
              'free_bytes': os.statvfs('/').f_bavail * os.statvfs('/').f_frsize}
    if action == 'source':
        module = importlib.util.spec_from_file_location('migration_state', str(Path(__file__).with_name('state.py')))
        state = importlib.util.module_from_spec(module)
        module.loader.exec_module(state)
        name, _ = state.database()
        clusters = state.run('pg_lsclusters', '--no-header', stdout=subprocess.PIPE, text=True).stdout.splitlines()
        rows = [line.split() for line in clusters if line.strip()]
        if len(rows) != 1 or rows[0][0] != '16' or rows[0][2] != '5432' or not re.fullmatch(r'[A-Za-z0-9_-]+', rows[0][1]):
            raise ValueError('single_default_postgresql16_cluster_required')
        result['pg_unit'] = 'postgresql@16-' + rows[0][1] + '.service'
        spec = state.spec()
        if spec.get('role') != 'bridge':
            raise ValueError('source_not_bridge')
        # paths() validates the supported TLS/Certbot selection before any stop.
        selected = state.paths()
        result['state_bytes'] = sum(p.stat().st_size for path in selected for p in ([path] if path.is_file() else path.rglob('*')) if p.is_file())
        result['database_bytes'] = int(state.run('runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-d', name,
                                               '-c', 'SELECT pg_database_size(current_database())', stdout=subprocess.PIPE, text=True).stdout.strip())
        version = state.run('runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-d', name,
                            '-c', 'SHOW server_version_num', stdout=subprocess.PIPE, text=True).stdout.strip()
        result['pg_major'] = int(version) // 10000
        primary = state.run('runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-d', name, '-c', 'SELECT pg_is_in_recovery()', stdout=subprocess.PIPE, text=True).stdout.strip()
        if primary != 'f':
            raise ValueError('source_primary_required')
        result['bridge_address'] = state.environment().get('ULTRA_VULTR_BRIDGE_IP')
        result['public_host'] = spec.get('public_host')
        result['database'] = name
        deployment = json.loads(Path('/etc/ultra-recovery/deployment.json').read_text())
        ingress = deployment.get('ingress') or {}
        result['forward_host'] = ingress.get('forward_host', '')
        if result['forward_host']:
            result['subscription_domain'] = ingress['domain']
        else:
            policy = json.loads(Path('/etc/ultra-recovery/dns.json').read_text())
            if set(policy.get('desired', {})) != {'subscription', 'vpn'}:
                raise ValueError('managed_direct_dns_migration_required')
            result['subscription_domain'] = policy['desired']['subscription']['name'] + '.' + policy['config']['zone']
            if policy['desired']['vpn']['name'] + '.' + policy['config']['zone'] != result['public_host']:
                raise ValueError('managed_public_dns_identity_mismatch')
        result['new_primary_provider'] = json.loads(Path('/etc/ultra-recovery/deployment.json').read_text()).get('bridge_provider')
    elif action == 'target':
        if Path('/etc/ultra-relay/spec.json').exists() or any(Path('/etc/letsencrypt/live').glob('*')):
            raise ValueError('unrelated_target_state')
        psql = subprocess.run(['which', 'psql'], stdout=subprocess.PIPE, check=False)
        if psql.returncode == 0:
            version = subprocess.run(['psql', '--version'], stdout=subprocess.PIPE, check=True).stdout.decode()
            match = re.search(r'PostgreSQL\) ([0-9]+)', version)
            result['pg_major'] = int(match.group(1)) if match else 0
            databases = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-d', 'postgres',
                                        '-c', "SELECT count(*) FROM pg_database WHERE datname NOT IN ('postgres','template0','template1')"],
                                       stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True).stdout.strip()
            if databases != b'0':
                raise ValueError('unrelated_target_database')
    else:
        raise ValueError('invalid_inventory_role')
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('migration_inventory_failed', file=sys.stderr)
        raise SystemExit(1)
