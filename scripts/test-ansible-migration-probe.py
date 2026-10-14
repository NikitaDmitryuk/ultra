#!/usr/bin/env python3
"""Target-bound payload regression; no servers or private runtime files needed."""
import base64
import importlib.util
import json
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / 'deploy/ansible/roles/bridge_migration/files/probe.py'
spec = importlib.util.spec_from_file_location('migration_probe', path)
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class TargetProfile(unittest.TestCase):
    def profile(self):
        return {'outbounds': [{'protocol': 'vless', 'tag': 'old', 'settings': {'vnext': [
            {'address': 'old.example.com', 'port': 443, 'users': [{'id': 'example-credential'}]}]},
            'streamSettings': {'security': 'reality', 'realitySettings': {'serverName': 'example.net'}}},
            {'protocol': 'freedom', 'tag': 'direct'}],
            'routing': {'rules': [{'outboundTag': 'direct'}]}, 'observatory': {'subjectSelector': ['old']}}

    def test_payload_cannot_pass_using_old_bridge_or_direct(self):
        config = probe.target_profile(self.profile(), '192.0.2.20')
        self.assertEqual(len(config['outbounds']), 1)
        outbound = config['outbounds'][0]
        self.assertEqual(outbound['settings']['vnext'][0]['address'], '192.0.2.20')
        self.assertEqual(outbound['streamSettings']['realitySettings']['serverName'], 'example.net')
        self.assertEqual(config['routing']['rules'][0]['outboundTag'], outbound['tag'])
        self.assertNotIn('observatory', config)

    def test_export_wrappers_and_ambiguous_routes(self):
        encoded = base64.b64encode(json.dumps(self.profile()).encode()).decode()
        result = probe.target_profile({'profiles': [{'id': 'fast_tcp_reality', 'full_xray_config_base64': encoded}]}, '192.0.2.20')
        self.assertEqual(result['outbounds'][0]['settings']['vnext'][0]['address'], '192.0.2.20')
        config = self.profile();config['outbounds'].append(config['outbounds'][0])
        with self.assertRaises(ValueError):
            probe.target_profile(config, '192.0.2.20')


if __name__ == '__main__':
    unittest.main()
