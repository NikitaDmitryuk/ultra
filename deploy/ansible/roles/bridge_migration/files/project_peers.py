#!/usr/bin/python3
"""Pure local projection from the authenticated generation; no subprocesses."""
import json
from pathlib import Path
import sys


def project(directory, nodes):
    sys.path.insert(0, str(directory / 'runtime'))
    from restore_ansible import project_peer_inputs
    config = json.loads((directory / 'restore-config.json').read_text())
    return project_peer_inputs(config, directory / 'verified-generation', nodes)



if __name__ == '__main__':
    try:
        directory, output = Path(sys.argv[1]), Path(sys.argv[2])
        result = project(directory, json.loads((output / 'nodes.json').read_text()))
        path = output / 'inputs.json'
        path.write_text(json.dumps(result))
        path.chmod(0o600)
    except Exception:
        print('migration_peer_projection_failed', file=sys.stderr)
        raise SystemExit(1)
