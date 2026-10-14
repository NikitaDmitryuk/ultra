#!/usr/bin/python3
"""Check application trust/readiness; timer activation stays in Ansible."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def sha(path):
    source = Path(path)
    if not source.is_file() or source.is_symlink():
        raise ValueError('installed_artifact_invalid')
    result = hashlib.sha256()
    with source.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def main():
    manifest_path = '/opt/ultra-recovery/release-manifest.json'
    policy = json.loads(Path('/etc/ultra-ansible/auto-upgrade.json').read_text())
    if (not policy.get('repository') or not policy.get('required_checks') or
            policy.get('public_key_file') != '/etc/ultra-ansible/release-signing.pub' or
            policy.get('config_file') != '/etc/ultra-ansible/install.config'):
        raise ValueError('generated_signed_channel_required')
    subprocess.run(['/usr/bin/minisign', '-V', '-p', policy['public_key_file'], '-m', manifest_path,
                    '-x', manifest_path + '.minisig'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    manifest = json.loads(Path(manifest_path).read_text())
    version = sys.argv[1]
    if manifest['version'] != version or 'ansible-deploy-v1' not in manifest['capabilities']:
        raise ValueError('accepted_target_identity_mismatch')
    receipt = json.loads(Path('/var/lib/ultra-automation/release.json').read_text())
    if receipt.get('version') != version or not receipt.get('ready_at'):
        raise ValueError('verified_fleet_receipt_required')
    architecture = subprocess.run(['dpkg', '--print-architecture'], check=True, stdout=subprocess.PIPE).stdout.decode().strip()
    for component in ('ultra-relay', 'ultra-bot', 'ultra-client', 'ultra-install'):
        matches = [a for a in manifest['assets'] if a['name'] == component + '-linux-' + architecture]
        if len(matches) != 1:
            raise ValueError('unique_signed_artifact_required')
        target = '/opt/ultra-ansible/current/ultra-install' if component == 'ultra-install' else '/usr/local/bin/' + component
        if sha(target) != matches[0]['sha256']:
            raise ValueError('installed_artifact_mismatch')
    print(json.dumps({'version': version, 'source_commit': manifest['source_commit'],
                      'manifest_sha256': sha(manifest_path)}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('signed_channel_acceptance_failed', file=sys.stderr)
        raise SystemExit(1)
