#!/usr/bin/env python3
"""Disposable fixture firewall; records arguments without changing networking."""
import json
from pathlib import Path
import sys
state = Path('/var/lib/fixture-ufw-inactive')
log = Path('/var/lib/fixture-ufw.json')
if sys.argv[1:] == ['status']:
    print('Status: inactive' if state.exists() else 'Status: active')
else:
    calls = json.loads(log.read_text()) if log.exists() else []
    call = sys.argv[1:]
    if call in calls:
        print('Skipping adding existing rule')
    else:
        calls.append(call)
        log.write_text(json.dumps(calls))
        print('Rule added')
