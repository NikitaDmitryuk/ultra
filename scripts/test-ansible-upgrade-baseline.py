#!/usr/bin/env python3
"""Synthetic heterogeneous upgrade provenance: no live deployment access."""
import hashlib
import base64
import hmac
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
with patch.dict(sys.modules, {'ansible': types.ModuleType('ansible'), 'ansible.module_utils': types.ModuleType('ansible.module_utils'), 'ansible.module_utils.basic': types.SimpleNamespace(AnsibleModule=None)}):
    spec = importlib.util.spec_from_file_location('baseline', ROOT / 'deploy/ansible/library/ultra_upgrade_baseline.py')
    baseline = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(baseline)


class Baseline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        self.addCleanup(patch.stopall)
        patch.object(baseline, 'ROOT_UID', os.geteuid()).start()
        patch.object(baseline, 'OWNERSHIP_ROOT', self.root).start()
        patch.object(baseline, 'ADOPTION_ROOT', self.root / 'adoption').start()
        self.release = self.root / 'release'
        self.release.mkdir(mode=0o700)
        self.assets = []
        for name, data in [('ultra-relay-linux-amd64', b'operator relay'), ('ultra-client-linux-amd64', b'operator client')]:
            path = self.release / name
            path.write_bytes(data)
            path.chmod(0o600)
            self.assets.append({'name': name, 'size': len(data), 'sha256': baseline.digest(path)})
        self.manifest = {'version': 'v9.0.0', 'assets': self.assets}
        self.write(self.release / 'release-manifest.json', self.manifest)
        self.id = '11111111-2222-3333-4444-555555555555'
        self.op = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        self.address = '192.0.2.2'
        self.keys = '192.0.2.2 ssh-ed25519 Zml4dHVyZQ==\n'
        pins = self.root / 'known_hosts'
        pins.write_text(self.keys)
        pins.chmod(0o600)
        self.host = {'ansible_host': self.address, 'ultra_spec': {'role': 'exit'},
                     'ultra_relay_source': str(self.release / self.assets[0]['name']), 'ultra_relay_sha256': self.assets[0]['sha256']}
        self.request = {'inventory': {'all': {'vars': {'ansible_ssh_common_args': '-o UserKnownHostsFile=' + str(pins)},
                        'children': {'exits': {'hosts': {'exit_0': self.host}}}}}, 'variables': {'ultra_bootstrap_exit_host': 'exit_0'}}
        self.exit_proof = self.stage('exit', 'bootstrap-exit', self.request, {'verified': True, 'exit_host': 'exit_0'})
        checkpoint = baseline.ADOPTION_ROOT / self.op / 'checkpoint.json'
        checkpoint.parent.mkdir(mode=0o700, parents=True)
        baseline.ADOPTION_ROOT.chmod(0o700)
        binary = checkpoint.parent / 'rollback-relay'
        binary.write_bytes(b'emergency relay')
        binary.chmod(0o600)
        self.emergency = {'version': 'v8.0.0', 'assets': [{'name': 'ultra-relay-linux-amd64', 'size': binary.stat().st_size, 'sha256': baseline.digest(binary)}]}
        self.write(checkpoint, {'architecture': 'amd64', 'legacy': True, 'emergency_manifest': self.emergency})
        bridge = {'inventory': {'all': {'children': {'bridge': {'hosts': {'bridge': {'ansible_host': '192.0.2.1'}}}}}}, 'variables': {'ultra_lifecycle_id': self.op}}
        self.bridge_proof = self.stage('rollback', 'rollback-adoption', bridge, {'verified': True})
        self.bridge_proof.update(checkpoint=str(checkpoint), checkpoint_sha256=baseline.digest(checkpoint))
        self.exit_proof['alias'] = 'exit_0'
        self.input = {'remote_release': str(self.release), 'manifest': self.manifest, 'descriptor': {
            'manifest_sha256': baseline.digest(self.release / 'release-manifest.json'), 'bridge': self.bridge_proof, 'exits': {self.id: self.exit_proof}}}
        self.nodes = {self.id: {'address': self.address, 'pins': self.keys}}

    def write(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def stage(self, name, operation, request, result):
        path = self.root / name
        path.mkdir(mode=0o700)
        self.write(path / 'request.json', request)
        sha = baseline.digest(path / 'request.json')
        job = {'schema_version': 1, 'operation': operation, 'request_sha256': sha, 'binary_sha256': sha, 'attempt': 1}
        self.write(path / 'job.json', job)
        self.write(path / 'receipt.json', {**job, 'state': 'succeeded', 'result': result})
        return {'stage': str(path), 'request_sha256': sha}

    def verify(self):
        return baseline.verify(self.input, self.nodes, '192.0.2.1')

    def test_exact_operator_and_emergency_identities_are_independent(self):
        result = self.verify()
        self.assertEqual(result['exits'][self.id], self.manifest)
        self.assertEqual(result['bridge_relay'], self.emergency)
        self.assertNotEqual(result['bridge_relay']['assets'][0]['sha256'], result['exits'][self.id]['assets'][0]['sha256'])

    def test_no_successful_receipt_means_no_adopted_baseline(self):
        path = Path(self.exit_proof['stage']) / 'receipt.json'
        original = json.loads(path.read_text())
        for field, value in [('state', 'failed'), ('request_sha256', 'b' * 64), ('attempt', 2), ('binary_sha256', 'b' * 64), ('operation', 'bootstrap-bridge')]:
            changed = {**original, field: value}
            self.write(path, changed)
            with self.assertRaises(ValueError): self.verify()
        self.write(path, {**original, 'result': {'verified': False, 'exit_host': 'exit_0'}})
        with self.assertRaises(ValueError): self.verify()

    def test_legacy_schema_one_receipts_may_omit_attempt_only_as_a_pair(self):
        stage = Path(self.exit_proof['stage'])
        job_path, receipt_path = stage / 'job.json', stage / 'receipt.json'
        job, receipt = json.loads(job_path.read_text()), json.loads(receipt_path.read_text())
        job.pop('attempt'); receipt.pop('attempt')
        self.write(job_path, job); self.write(receipt_path, receipt)
        self.verify()
        receipt['attempt'] = 1
        self.write(receipt_path, receipt)
        with self.assertRaises(ValueError): self.verify()
        receipt.pop('attempt'); job['attempt'] = 1
        self.write(job_path, job); self.write(receipt_path, receipt)
        with self.assertRaises(ValueError): self.verify()

    def test_successful_bootstrap_receipt_still_needs_manifest_bound_host_vars(self):
        # LOCAL bootstrap-exit stores application variables in inventory, and
        # uses the request digest as binary_sha256. configure-exit differs.
        for field, replacement in [('ultra_relay_sha256', 'a' * 64),
                                   ('ultra_relay_source', str(self.root / 'unowned-relay')),
                                   ('ultra_spec', {'role': 'bridge'})]:
            original = self.host[field]
            self.host[field] = replacement
            stage = Path(self.exit_proof['stage'])
            self.write(stage / 'request.json', self.request)
            digest = baseline.digest(stage / 'request.json')
            self.exit_proof['request_sha256'] = digest
            for name in ('job.json', 'receipt.json'):
                value = json.loads((stage / name).read_text())
                value.update(request_sha256=digest, binary_sha256=digest)
                self.write(stage / name, value)
            with self.assertRaises(ValueError): self.verify()
            self.host[field] = original

    def test_user_writable_proof_ancestor_cannot_supply_root_evidence(self):
        stage = Path(self.exit_proof['stage'])
        stage.chmod(0o777)
        with self.assertRaises(ValueError): self.verify()

    def test_changed_retained_asset_cannot_be_blessed_by_active_identity(self):
        (self.release / self.assets[1]['name']).write_bytes(b'unknown client')
        with self.assertRaises(ValueError): self.verify()

    def test_inventory_address_and_host_key_must_match_frozen_topology(self):
        self.nodes[self.id]['address'] = '192.0.2.3'
        with self.assertRaises(ValueError): self.verify()

    def test_hashed_openssh_host_pin_must_match_the_frozen_address(self):
        salt = b'fixture-salt'
        hashed = '|1|' + base64.b64encode(salt).decode() + '|' + base64.b64encode(
            hmac.new(salt, self.address.encode(), hashlib.sha1).digest()).decode()
        text = hashed + ' ssh-ed25519 Zml4dHVyZQ==\n'
        self.assertEqual(baseline.pins(text, self.address), {('ssh-ed25519', 'Zml4dHVyZQ==')})
        with self.assertRaises(ValueError): baseline.pins(text, '192.0.2.3')
        self.nodes[self.id]['address'] = self.address
        self.nodes[self.id]['pins'] = self.keys.replace('Zml4dHVyZQ==', 'd3Jvbmc=')
        with self.assertRaises(ValueError): self.verify()

    def test_checkpoint_pin_and_restored_emergency_bytes_are_required(self):
        self.bridge_proof['checkpoint_sha256'] = 'c' * 64
        with self.assertRaises(ValueError): self.verify()
        self.bridge_proof['checkpoint_sha256'] = baseline.digest(self.bridge_proof['checkpoint'])
        (Path(self.bridge_proof['checkpoint']).parent / 'rollback-relay').write_bytes(b'unknown relay')
        with self.assertRaises(ValueError): self.verify()

    def test_private_root_proof_and_non_symlink_sources_are_required(self):
        proof = Path(self.exit_proof['stage']) / 'receipt.json'
        proof.chmod(0o644)
        with self.assertRaises(ValueError): self.verify()
        proof.chmod(0o600)
        source = self.release / self.assets[0]['name']
        source.rename(self.root / 'saved-relay')
        source.symlink_to(self.root / 'saved-relay')
        with self.assertRaises(ValueError): self.verify()

    def test_extra_and_missing_frozen_nodes_fail(self):
        self.nodes['ffffffff-ffff-ffff-ffff-ffffffffffff'] = self.nodes[self.id]
        with self.assertRaises(ValueError): self.verify()


if __name__ == '__main__': unittest.main()
