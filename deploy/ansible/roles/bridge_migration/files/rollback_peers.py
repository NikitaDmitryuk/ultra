#!/usr/bin/python3
"""Derive reverse replica requests from the original primary; no host mutation."""
import json
from pathlib import Path
import sys


def main():
    sys.path.insert(0, str(Path(__file__).parent))
    import state
    from restore_host import plan_peer_reseed, sql
    plan = json.load(sys.stdin)
    name, _ = state.database()
    identity = sql('SELECT system_identifier FROM pg_control_system()')
    print(json.dumps({'nodes': plan_peer_reseed(plan, name, identity)}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('migration_reverse_replica_plan_failed', file=sys.stderr)
        raise SystemExit(1)
