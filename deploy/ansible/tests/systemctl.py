#!/usr/bin/python3
"""Container fixture for service-manager calls; does not test a real systemd boot."""
import json
from pathlib import Path
import sys

path = Path('/var/lib/fixture-systemctl.json')
state = json.loads(path.read_text()) if path.exists() else {'active': False, 'enabled': False, 'restarts': 0}
arguments = [value for value in sys.argv[1:] if not value.startswith('--')]
command = arguments[0]
if command == 'show':
    print('LoadState=loaded\nActiveState=' + ('active' if state['active'] else 'inactive'))
    print('UnitFileState=' + ('enabled' if state['enabled'] else 'disabled'))
    print('CanReload=no\nNeedDaemonReload=no')
elif command == 'is-enabled':
    print('enabled' if state['enabled'] else 'disabled')
    raise SystemExit(0 if state['enabled'] else 1)
elif command == 'enable':
    state['enabled'] = True
elif command in ('start', 'restart'):
    state['active'] = True
    state['activations'] = state.get('activations', 0) + 1
    if command == 'restart':
        state['restarts'] += 1
elif command == 'stop':
    state['active'] = False
elif command not in ('daemon-reload', 'reset-failed'):
    raise SystemExit('unsupported fixture command')
path.write_text(json.dumps(state))
