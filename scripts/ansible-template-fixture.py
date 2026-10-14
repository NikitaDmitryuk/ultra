"""Test-only rendering of simple role placeholders; roles remain the source."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def render(name, values):
    source = (ROOT / 'deploy/ansible/roles/ingress/templates' / name).read_text()
    def replace(match):
        key = match.group(1).strip()
        if key not in values:
            raise ValueError('fixture variable missing: ' + key)
        return str(values[key])
    rendered = re.sub(r'{{\s*([^}]+)\s*}}', replace, source)
    if '{%' in rendered or '{{' in rendered:
        raise ValueError('unsupported fixture expression')
    return rendered.encode()


def nginx(params, port=443):
    if 'path' in params:
        return render('primary.conf.j2', {'ultra_ingress.domain': params['domain'], 'ultra_ingress.path': params['path'],
                                         'ultra_ingress.backend_port': params['backend_port'], 'ingress_public_port': port})
    return render('subscription.conf.j2', {'ultra_subscription_domain': params['domain'], 'ultra_bot_port': params['bot_port'],
                                         'ultra_bot_domain': params['upstream_domain']})
