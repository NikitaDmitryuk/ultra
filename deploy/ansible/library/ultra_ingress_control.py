#!/usr/bin/python
"""Read-only status and durable application notice enqueueing for operator ingress CLI."""
import json
from pathlib import Path
import urllib.request
from ansible.module_utils.basic import AnsibleModule


def main():
    module = AnsibleModule(argument_spec={
        'action': {'type': 'str', 'choices': ['status', 'notice'], 'required': True},
        'notice_key': {'type': 'str', 'default': ''},
        'notice_text': {'type': 'str', 'default': '', 'no_log': True},
    }, supports_check_mode=True)
    try:
        values = {}
        for line in Path('/etc/ultra-relay/environment').read_text().splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                values[key] = value.strip().strip('"').strip("'")
        action = module.params['action']
        if action == 'notice' and module.check_mode:
            module.exit_json(changed=True)
        payload = json.dumps({'key': module.params['notice_key'], 'text': module.params['notice_text']}).encode() if action == 'notice' else None
        endpoint = '/v1/ingress/notice' if action == 'notice' else '/v1/hardening'
        request = urllib.request.Request('http://127.0.0.1:8443' + endpoint, data=payload,
            headers={'Authorization': 'Bearer ' + values['ULTRA_RELAY_ADMIN_TOKEN'], 'Content-Type': 'application/json'})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=10) as response:
            data = json.load(response)
        module.exit_json(changed=action == 'notice' and data.get('queued', False), ready=True)
    except (OSError, KeyError, ValueError):
        module.fail_json(msg='ingress_application_control_failed')


if __name__ == '__main__':
    main()
