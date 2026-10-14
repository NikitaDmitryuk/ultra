#!/usr/bin/python3
"""Operator-local generation proof: the private age identity never reaches a VM."""
import json
from pathlib import Path
import sys


def main():
    directory = Path(sys.argv[1])
    sys.path.insert(0, str(directory / 'runtime'))
    from recovery import atomic_json
    from restore import stage_generation
    from restore_common import configuration, plan_id, sha
    config = configuration(json.loads((directory / 'restore-config.json').read_text()))
    work = directory / 'verified-generation'
    work.mkdir(mode=0o700, exist_ok=True)
    state, _, archive = stage_generation(config, work)
    run_id = plan_id(config, sha(config['bundle']))
    binary = (work / 'stage/artifacts/usr/local/bin/ultra-relay').read_bytes()[:20]
    if binary[:4] != b'\x7fELF' or binary[5] != 1 or int.from_bytes(binary[18:20], 'little') not in (62, 183):
        raise ValueError('supported_binary_required')
    architecture = {62: 'x86_64', 183: 'aarch64'}[int.from_bytes(binary[18:20], 'little')]
    plan = {key: config[key] for key in ('old_bridge_address', 'new_bridge_address', 'public_host', 'subscription_domain', 'new_bridge_provider', 'ingress_mode')}
    if config.get('migration_identity'):
        plan['migration_identity'] = config['migration_identity']
    plan.update(architecture=architecture, restore_id=run_id, target_host=config['target']['host'], readiness_timeout=900,
                stage_sha256=sha(archive), fence=json.loads(Path(config['fence_file']).read_text()))
    atomic_json(directory / 'restore-plan.json', {'plan': plan, 'archive': str(archive), 'snapshot_at': state['snapshot_at']})


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('migration_generation_proof_failed', file=sys.stderr)
        raise SystemExit(1)
