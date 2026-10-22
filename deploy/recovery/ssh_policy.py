"""Load the versioned operator SSH policy shipped beside recovery tools."""
import json
from pathlib import Path


def load_policy():
    path = Path(__file__).with_name('ssh_policy.json')
    value = json.loads(path.read_text(encoding='utf-8'))
    if value.get('version') != 1:
        raise ValueError('unsupported_ssh_policy_version')
    return value


POLICY = load_policy()


def ssh_options(kind='probe'):
    timeout = POLICY['mutate_connect_timeout_seconds'] if kind == 'mutate' else POLICY['probe_connect_timeout_seconds']
    return ['-o', 'ConnectTimeout=' + str(timeout),
            '-o', 'ServerAliveInterval=' + str(POLICY['server_alive_interval_seconds']),
            '-o', 'ServerAliveCountMax=' + str(POLICY['server_alive_count_max']),
            '-o', 'StrictHostKeyChecking=' + POLICY['strict_host_key_checking'],
            '-o', 'UpdateHostKeys=' + POLICY['update_host_keys']]
