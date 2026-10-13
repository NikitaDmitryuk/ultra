#!/usr/bin/env python3
"""Restricted SSH forced-command: emit only bounded monitor heartbeat fields."""
import json
from recovery import private

raw = private('/var/lib/ultra-monitor/heartbeat.json').read_bytes()
if len(raw) > 4096:
    raise SystemExit(1)
value = json.loads(raw)
checks = value.get('checks', {})
if not isinstance(checks, dict) or len(checks) > 16 or any(not isinstance(k, str) or len(k) > 64 or not isinstance(v, bool) for k, v in checks.items()):
    raise SystemExit(1)
updated = value.get('updated_at')
pending = value.get('pending', 0)
error = value.get('send_error')
if not isinstance(updated, (int, float)) or not isinstance(pending, int) or not 0 <= pending <= 100 or error not in (None, 'telegram_recipient_blocked', 'telegram_unavailable'):
    raise SystemExit(1)
print(json.dumps({'updated_at': updated, 'checks': checks, 'pending': pending, 'send_error': error}))
