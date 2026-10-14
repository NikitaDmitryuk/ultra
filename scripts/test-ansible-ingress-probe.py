"""Application listener probes honor a preserved custom loopback address."""
import importlib.util
import json
from pathlib import Path
import tempfile
import ssl
from unittest.mock import patch

source = Path(__file__).resolve().parents[1] / 'deploy/ansible/library/ultra_ingress_probe.py'
spec = importlib.util.spec_from_file_location('probe', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with tempfile.TemporaryDirectory() as folder:
    file = Path(folder) / 'spec.json'
    with patch.object(module, 'Path', return_value=file):
        file.write_text(json.dumps({'admin_listen': '127.0.0.1:28443'}))
        assert module.relay_endpoint() == 'http://127.0.0.1:28443/v1/hardening'
        file.write_text(json.dumps({'admin_listen': '[::1]:28443'}))
        assert module.relay_endpoint() == 'http://[::1]:28443/v1/hardening'
        for address in ['192.0.2.1:28443', '127.0.0.1:28443/path', 'secret@127.0.0.1:28443', '127.0.0.1:70000']:
            file.write_text(json.dumps({'admin_listen': address}))
            try:
                module.relay_endpoint()
            except ValueError:
                pass
            else:
                raise AssertionError('unsafe endpoint accepted')
print('native ingress readiness preserves custom loopback listener')

# Exercise both client entry points with real SSL contexts. A rejected connection
# stops before HTTP parsing while allowing inspection of the handshake policy.
for probe in ('bot', 'tls'):
    context = ssl.create_default_context()
    with patch.object(module, 'verified_client_context', return_value=context) as factory, \
            patch.object(module.socket, 'create_connection', side_effect=OSError('fixture connection stopped')), \
            patch.object(module.Path, 'read_text', return_value='ULTRA_BOT_PORT=443\nULTRA_BOT_DOMAIN=example.com\n'):
        try:
            module.bot_ready() if probe == 'bot' else module.tls_ready('127.0.0.1', 'example.com', 443)
        except OSError:
            pass
        else:
            raise AssertionError('fixture should stop connection')
    factory.assert_called_once_with()
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname
print('all ingress TLS clients require TLS 1.2 and verified host certificates')

# The explicit client context must preserve the standard library's platform
# trust anchors and chain verification policy, which varies by Python version.
default_context = ssl.create_default_context()
client_context = module.verified_client_context()
assert client_context.protocol == ssl.PROTOCOL_TLS_CLIENT
assert client_context.minimum_version == ssl.TLSVersion.TLSv1_2
assert client_context.verify_mode == ssl.CERT_REQUIRED
assert client_context.check_hostname
assert client_context.verify_flags == default_context.verify_flags
assert client_context.get_ca_certs(binary_form=True) == default_context.get_ca_certs(binary_form=True)
print('explicit TLS client preserves default certificate-chain and hostname verification')
