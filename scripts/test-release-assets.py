#!/usr/bin/env python3
"""Verify the actual release publication against generated manifest/checksums."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
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
    required = manifest_names | checksum_names | {'checksums.txt', 'release-manifest.json', 'checksums.txt.minisig', 'release-manifest.json.minisig'}
    missing = {'dist/' + name for name in required} - published_assets(workflow)
    if missing:
        raise AssertionError('release assets not published: ' + ', '.join(sorted(missing)))


def archive_files(path):
    with tarfile.open(path, 'r:gz') as archive:
        result = {}
        for member in archive.getmembers():
            name = member.name.removeprefix('./')
            if member.isdir():
                continue
            if not member.isfile() or name.startswith('/') or '..' in Path(name).parts or name in result:
                raise AssertionError('unsafe or duplicate archive entry: ' + member.name)
            result[name] = archive.extractfile(member).read()
        return result


def validate_bundle(directory, workflow):
    """Inspect actual build output without executing downloaded binaries or wheels."""
    manifest = json.loads((directory / 'release-manifest.json').read_text())
    checksums = (directory / 'checksums.txt').read_text()
    expected = set(release_inventory((ROOT / 'Makefile').read_text())) | {'checksums.txt'}
    rows = manifest['assets']
    assert len(expected) == 14 and len(rows) == 14 and {row['name'] for row in rows} == expected, 'complete 14-asset manifest required'
    assert manifest['schema_version'] == 1 and re.fullmatch('[0-9a-f]{40}', manifest['source_commit']), 'invalid manifest provenance'
    assert manifest['database_schema_min'] == 24 and manifest['database_schema_max'] == 25, 'unexpected database range'
    assert {'service-access-v1', 'provider-pool-quota-v1', 'lifecycle-gate-v1'} <= set(manifest['capabilities']), 'missing required capabilities'
    assert_publication(workflow, manifest, checksums)
    checksum_rows = {}
    for line in checksums.splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([^/]+)', line)
        assert match and match[2] not in checksum_rows, 'invalid or duplicate checksum row'
        checksum_rows[match[2]] = match[1]
    assert set(checksum_rows) == expected - {'checksums.txt'}, 'incomplete checksum inventory'
    for row in rows:
        raw = (directory / row['name']).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        assert raw and row['size'] == len(raw) and row['sha256'] == digest, 'manifest mismatch: ' + row['name']
        if row['name'] != 'checksums.txt':
            assert checksum_rows[row['name']] == digest, 'checksum mismatch: ' + row['name']
    for architecture, machine in [('amd64', 62), ('arm64', 183)]:
        for application in ['install', 'relay', 'bot', 'client']:
            name = 'ultra-' + application + '-linux-' + architecture
            with (directory / name).open('rb') as binary:
                header = binary.read(20)
            assert header[:6] == b'\x7fELF\x02\x01' and int.from_bytes(header[18:20], 'little') == machine, 'wrong ELF architecture: ' + name
        runtime = archive_files(directory / ('ultra-ansible-runtime-linux-' + architecture + '.tar.gz'))
        pins = (ROOT / 'deploy/ansible/requirements.txt').read_text().splitlines()
        locked = runtime.pop('requirements.lock').decode().splitlines()
        assert [line.split(' --hash=', 1)[0] for line in locked] == pins, 'runtime pins differ from source'
        assert runtime and all(re.fullmatch(r'wheels/[^/]+\.whl', name) for name in runtime), 'unexpected runtime archive contents'
        for name, raw in runtime.items():
            package, version = Path(name).name.split('-')[:2]
            pin = package.replace('_', '-').lower() + '==' + version
            matching = [line for line in locked if line.split(' --hash=', 1)[0].replace('_', '-').lower() == pin]
            assert len(matching) == 1 and ' --hash=sha256:' + hashlib.sha256(raw).hexdigest() in matching[0], 'unlocked runtime wheel: ' + name
            assert name.endswith('-none-any.whl') or 'manylinux' in name and ('x86_64' if architecture == 'amd64' else 'aarch64') in name, 'wrong wheel architecture: ' + name
        for line in locked:
            package, version = line.split(' --hash=', 1)[0].split('==')
            wheels = [name for name in runtime if Path(name).name.lower().startswith(package.replace('-', '_').lower() + '-' + version + '-')]
            assert set(re.findall(r' --hash=sha256:([0-9a-f]{64})', line)) == {hashlib.sha256(runtime[name]).hexdigest() for name in wheels}, 'runtime lock contains missing wheels'
            for python in [312, 313, 314]:
                assert any('-none-any.whl' in name or '-cp' + str(python) + '-' in name or re.search(r'-cp(\d+)-abi3-', name) and int(re.search(r'-cp(\d+)-abi3-', name)[1]) <= python for name in wheels), 'wheel missing for Python ' + str(python) + ': ' + package
    ansible = archive_files(directory / 'ultra-ansible.tar.gz')
    assert {'ansible.cfg', 'requirements.txt', 'controller.py', 'playbooks/bootstrap.yml', 'playbooks/upgrade.yml'} <= ansible.keys(), 'incomplete Ansible sources'
    expected_ansible = {path.relative_to(ROOT / 'deploy/ansible').as_posix() for path in (ROOT / 'deploy/ansible').rglob('*') if path.is_file() and '__pycache__' not in path.parts and path.suffix != '.pyc' and (path.relative_to(ROOT / 'deploy/ansible').parts[0] in ['playbooks', 'roles', 'library', 'callback_plugins'] or path.name in ['ansible.cfg', 'requirements.txt', 'controller.py'])}
    assert set(ansible) == expected_ansible, 'incomplete Ansible source inventory'
    for name, raw in ansible.items():
        source = ROOT / 'deploy/ansible' / name
        assert source.is_file() and source.read_bytes() == raw, 'Ansible archive differs from source: ' + name
    recovery = archive_files(directory / 'ultra-recovery.tar.gz')
    required_recovery = {path.name for path in (ROOT / 'deploy/recovery').iterdir() if path.suffix in ['.py', '.service', '.timer'] and not path.name.startswith(('test_', 'vm_', 'test-'))}
    assert set(recovery) == required_recovery, 'incomplete recovery tools'
    for name, raw in recovery.items():
        assert (ROOT / 'deploy/recovery' / name).read_bytes() == raw, 'recovery archive differs from source: ' + name
    assert (directory / 'mobile-bootstrap.sh').read_bytes() == (ROOT / 'deploy/mobile-bootstrap.sh').read_bytes(), 'mobile bootstrap differs from source'


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
        for name in ['ultra-client-linux-amd64', 'ultra-client-linux-arm64', 'ultra-recovery.tar.gz', 'checksums.txt', 'release-manifest.json', 'checksums.txt.minisig', 'release-manifest.json.minisig']:
            with self.subTest(asset=name):
                altered = self.workflow.replace('            dist/' + name + '\n', '')
                self.assertNotEqual(altered, self.workflow)
                with self.assertRaisesRegex(AssertionError, 'release assets not published'):
                    assert_publication(altered, self.manifest, self.checksums)

    def test_manifest_generator_rejects_missing_and_empty_assets_atomically(self):
        original = (self.directory / 'release-manifest.json').read_bytes()
        for name in self.names + ['checksums.txt']:
            with self.subTest(asset=name):
                path = self.directory / name
                raw = path.read_bytes()
                for empty in [False, True]:
                    if empty:
                        path.write_bytes(b'')
                    else:
                        path.unlink()
                    result = subprocess.run(['bash', str(ROOT / 'scripts/build-release-manifest.sh'), str(self.directory), 'fixture'], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('missing or empty asset: ' + name, result.stderr)
                    self.assertEqual((self.directory / 'release-manifest.json').read_bytes(), original)
                    path.write_bytes(raw)

    def test_actual_bundle_validation_rejects_synthetic_binaries(self):
        with self.assertRaisesRegex(AssertionError, 'wrong ELF architecture'):
            validate_bundle(self.directory, self.workflow)

    def test_checksum_asset_missing_from_manifest_is_detected(self):
        manifest = dict(self.manifest, assets=[row for row in self.manifest['assets'] if row['name'] != 'ultra-recovery.tar.gz'])
        with self.assertRaisesRegex(AssertionError, 'checksum assets absent from manifest'):
            assert_publication(self.workflow, manifest, self.checksums)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--dist', type=Path, help='inspect a real unsigned release-dist before signing')
    arguments, remaining = parser.parse_known_args()
    if arguments.dist:
        validate_bundle(arguments.dist, (ROOT / '.github/workflows/release.yml').read_text())
        print('Actual release bundle validated: ' + str(arguments.dist))
    else:
        unittest.main(argv=[__file__] + remaining)
