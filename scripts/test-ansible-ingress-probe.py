"""Application listener probes honor a preserved custom loopback address."""
import importlib.util
import json
from pathlib import Path
import tempfile
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
