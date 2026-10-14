#!/usr/bin/env python3
"""Read-only readiness evidence for primary recovery automation."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import time


def independent_generation(config, state, reconcile, backup):
    primary = state.get('primary')
    nodes = state.get('node_metadata')
    delivered = backup.get('delivered_target_ids')
    if (not isinstance(primary,str) or not primary or reconcile.get('primary') != primary
            or not isinstance(nodes,list) or not isinstance(delivered,list)
            or primary not in delivered or not all(isinstance(x,str) for x in delivered)):
        return False
    selected = [node for node in nodes if isinstance(node,dict) and node.get('id') == primary]
    provider = config.get('bridge_provider')
    if (len(selected) != 1 or not isinstance(provider,str)
            or not isinstance(selected[0].get('provider'),str)
            or selected[0]['provider'].lower() == provider.lower()):
        return False
    return (backup.get('source') == 'bridge'
            and isinstance(backup.get('backup_name'),str)
            and re.fullmatch(r'[a-f0-9]{64}',backup.get('backup_sha256','')) is not None
            and re.fullmatch(r'[a-f0-9]{64}',backup.get('artifact_sha256','')) is not None)


def status(not_before):
    reasons = []
    independent = False
    try:
        reconcile = json.loads(Path('/var/lib/ultra-relay/recovery-reconcile-status.json').read_text())
        backup = json.loads(Path('/var/lib/ultra-recovery/last-success.json').read_text())
        now = time.time()
        config = json.loads(Path('/etc/ultra-recovery/reconcile.json').read_text())
        state = json.loads((Path(config['state_dir']) / 'state.json').read_text())
        independent = reconcile.get('independent') is True and independent_generation(config,state,reconcile,backup)
        if reconcile.get('state') != 'ready':
            reasons.append('controller_pending')
        if not independent:
            reasons.append('independent_destination_unavailable')
        if not 0 <= now - state['updated_at'] <= 180:
            reasons.append('controller_topology_stale')
        if not 0 <= now - reconcile['updated_at'] <= 180:
            reasons.append('controller_status_stale')
        if not 0 <= now - backup['snapshot_at'] <= 300:
            reasons.append('backup_stale')
        if state['updated_at'] <= not_before or reconcile['updated_at'] <= not_before or backup['snapshot_at'] <= not_before:
            reasons.append('evidence_before_activation')
        database = config['database']
        if not re.fullmatch(r'[A-Za-z0-9_-]+', database):
            raise ValueError('invalid_database')
        query = "SELECT count(*)>0 AND bool_and(COALESCE(r.state='streaming' AND r.checked_at>now()-interval '90 seconds',false)) FROM exit_nodes n LEFT JOIN node_replication r ON r.node_id=n.id WHERE n.enabled"
        result = subprocess.run(['runuser', '-u', 'postgres', '--', 'psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-d', database, '-c', query],
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        if result.returncode or result.stdout.strip() != b't':
            reasons.append('replica_not_fresh_streaming')
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        reasons.append('readiness_evidence_unavailable')
    return {'verified': not reasons, 'ready': not reasons, 'independent': independent, 'reasons': sorted(set(reasons))}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--not-before', type=int, required=True)
    value = status(parser.parse_args().not_before)
    print(json.dumps(value))
    raise SystemExit(0 if value['ready'] else 2)
