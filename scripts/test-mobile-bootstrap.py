#!/usr/bin/env python3
"""Loader checks use synthetic release files and no network or root operations."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class LoaderTests(unittest.TestCase):
    def test_complete_immutable_bundle_and_tamper_refusal(self):
        with tempfile.TemporaryDirectory(prefix='ultra-mobile-loader-') as temporary:
            directory = Path(temporary); release = directory / 'release'; release.mkdir()
            names = [f'ultra-{app}-linux-{arch}' for app in ('install', 'relay', 'bot', 'client') for arch in ('amd64', 'arm64')]
            names += ['ultra-recovery.tar.gz', 'ultra-ansible.tar.gz', 'ultra-ansible-runtime-linux-amd64.tar.gz', 'ultra-ansible-runtime-linux-arm64.tar.gz']
            for name in names:
                data = b'fixture'
                if name == 'ultra-install-linux-amd64':
                    data = b'#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n'
                (release / name).write_bytes(data)
            (release / 'checksums.txt').write_text(''.join(hashlib.sha256((release / name).read_bytes()).hexdigest() + '  ' + name + '\n' for name in names))
            def manifest():
                (release / 'release-manifest.json').write_text(json.dumps({'version': 'v2.5.0', 'assets': [
                    {'name': name, 'size': (release / name).stat().st_size, 'sha256': hashlib.sha256((release / name).read_bytes()).hexdigest()}
                    for name in names + ['checksums.txt']]}))
            manifest()
            commands = directory / 'commands'; commands.mkdir()
            (commands / 'id').write_text('#!/bin/sh\nprintf "0\\n"\n'); (commands / 'id').chmod(0o755)
            (commands / 'curl').write_text('#!/usr/bin/env python3\nimport os,pathlib,shutil,sys\nout=sys.argv[sys.argv.index("-o")+1];name=sys.argv[-1].rsplit("/",1)[-1]\nshutil.copyfile(pathlib.Path(os.environ["FIXTURE_RELEASE"])/name,out)\n'); (commands / 'curl').chmod(0o755)
            env = dict(os.environ, PATH=str(commands) + ':' + os.environ['PATH'], FIXTURE_RELEASE=str(release))
            root = directory / 'installed'
            def invoke():
                plan = directory / 'plan.json'; plan.write_text('{}'); plan.chmod(0o600)
                return subprocess.run(['bash', str(ROOT / 'deploy/mobile-bootstrap.sh'), '--plan', str(plan), '--install-root', str(root), '--require-signature', 'no'], env=env, capture_output=True, text=True)
            first = invoke(); self.assertEqual(first.returncode, 0, first.stderr)
            selected = root / 'releases/v2.5.0-amd64'
            self.assertEqual(json.loads(first.stdout)[0], 'apply-remote')
            for name in names:
                self.assertEqual((selected / name).read_bytes(), (release / name).read_bytes())
            repeated = invoke(); self.assertEqual(repeated.returncode, 0, repeated.stderr)
            original = (selected / names[0]).read_bytes()
            (release / names[0]).write_bytes(b'changed but signed-looking fixture'); manifest()
            conflict = invoke(); self.assertNotEqual(conflict.returncode, 0)
            self.assertIn('immutable release', conflict.stderr)
            self.assertIn('conflict', conflict.stderr)
            self.assertEqual((selected / names[0]).read_bytes(), original)

    def test_default_signature_requires_trusted_public_key_before_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); commands = directory / 'commands'; commands.mkdir()
            (commands / 'id').write_text('#!/bin/sh\nprintf "0\\n"\n'); (commands / 'id').chmod(0o755)
            marker = directory / 'downloaded'
            (commands / 'curl').write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nexit 1\n'); (commands / 'curl').chmod(0o755)
            plan = directory / 'plan'; plan.write_text('{}')
            result = subprocess.run(['bash', str(ROOT / 'deploy/mobile-bootstrap.sh'), '--plan', str(plan)],
                                    env=dict(os.environ, PATH=str(commands) + ':' + os.environ['PATH']), capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('trusted minisign public key required', result.stderr)
            self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
