#!/usr/bin/env python3
"""Verify the actual release publication against generated manifest/checksums."""
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def release_inventory(makefile):
    variables = dict(re.findall(r'^([A-Z_]+)=([^\n]+)$', makefile, re.MULTILINE))
    match = re.search(r'\(cd dist && sha256sum\s+(.*?)> checksums\.txt\)', makefile, re.DOTALL)
    if not match:
        raise AssertionError('release-dist checksum inventory not found')
    body = match[1].replace('\\\n', ' ')
    body = re.sub(r'\$\(([A-Z_]+)\)', lambda m: variables[m[1]], body)
    names = shlex.split(body)
    if not names or any(Path(name).name != name for name in names):
        raise AssertionError('expected literal release asset basenames')
    return names


def published_assets(workflow):
    # This is intentionally a narrow reader for the checked-in literal block,
    # not a second YAML implementation. Unsupported syntax fails the contract.
    steps = re.split(r'^      - ', workflow, flags=re.MULTILINE)
    published = set()
    for step in steps:
        if not re.search(r'^        uses: softprops/action-gh-release@', step, re.MULTILINE):
            continue
        match = re.search(r'^          files: \|\n((?:            [^\n]+\n)+)', step, re.MULTILINE)
        if not match:
            raise AssertionError('literal release publication files block required')
        published.update(line.strip() for line in match[1].splitlines())
    if not published:
        raise AssertionError('GitHub Release publication step not found')
    return published


def assert_publication(workflow, manifest, checksums):
    manifest_names = {row['name'] for row in manifest['assets']}
    checksum_names = {line.split('  ', 1)[1] for line in checksums.splitlines()}
    missing_manifest = checksum_names - manifest_names
    if missing_manifest:
        raise AssertionError('checksum assets absent from manifest: ' + ', '.join(sorted(missing_manifest)))
    required = manifest_names | checksum_names | {'checksums.txt', 'release-manifest.json'}
    missing = {'dist/' + name for name in required} - published_assets(workflow)
    if missing:
        raise AssertionError('release assets not published: ' + ', '.join(sorted(missing)))


class ReleaseAssets(unittest.TestCase):
    def setUp(self):
        self.workflow = (ROOT / '.github/workflows/release.yml').read_text()
        self.names = release_inventory((ROOT / 'Makefile').read_text())
        self.temporary = tempfile.TemporaryDirectory(prefix='ultra-release-contract-')
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        entries = []
        for name in self.names:
            data = ('synthetic release asset: ' + name).encode()
            (self.directory / name).write_bytes(data)
            entries.append(hashlib.sha256(data).hexdigest() + '  ' + name + '\n')
        self.checksums = ''.join(entries)
        (self.directory / 'checksums.txt').write_text(self.checksums)
        subprocess.run(['bash', str(ROOT / 'scripts/build-release-manifest.sh'), str(self.directory), 'fixture-contract'], check=True)
        self.manifest = json.loads((self.directory / 'release-manifest.json').read_text())

    def test_actual_publication_covers_generated_manifest_and_checksums(self):
        assert_publication(self.workflow, self.manifest, self.checksums)
        for row in self.manifest['assets']:
            raw = (self.directory / row['name']).read_bytes()
            self.assertEqual(row['sha256'], hashlib.sha256(raw).hexdigest())
            self.assertEqual(row['size'], len(raw))

    def test_missing_required_uploads_are_detected(self):
        for name in ['ultra-client-linux-amd64', 'ultra-client-linux-arm64', 'ultra-recovery.tar.gz', 'checksums.txt', 'release-manifest.json']:
            with self.subTest(asset=name):
                altered = self.workflow.replace('            dist/' + name + '\n', '')
                self.assertNotEqual(altered, self.workflow)
                with self.assertRaisesRegex(AssertionError, 'release assets not published'):
                    assert_publication(altered, self.manifest, self.checksums)

    def test_checksum_asset_missing_from_manifest_is_detected(self):
        manifest = dict(self.manifest, assets=[row for row in self.manifest['assets'] if row['name'] != 'ultra-recovery.tar.gz'])
        with self.assertRaisesRegex(AssertionError, 'checksum assets absent from manifest'):
            assert_publication(self.workflow, manifest, self.checksums)


if __name__ == '__main__':
    unittest.main()
