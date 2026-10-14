#!/usr/bin/env python3
"""Build an offline, hashed Ansible runtime for Linux amd64/arm64 and Python 3.12–3.14."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

PINS = (Path(__file__).resolve().parents[1] / 'deploy/ansible/requirements.txt').read_text().splitlines()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--architecture', choices=['amd64', 'arm64'], required=True)
    parser.add_argument('--output', required=True)
    arguments = parser.parse_args()
    architecture = {'amd64': 'x86_64', 'arm64': 'aarch64'}[arguments.architecture]
    output = Path(arguments.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='ultra-ansible-runtime-') as temporary:
        root = Path(temporary)
        wheels = root / 'wheels'
        wheels.mkdir()
        for version in ('3.12', '3.13', '3.14'):
            command = [sys.executable, '-m', 'pip', 'download', '--only-binary=:all:', '--no-deps',
                       '--python-version', version, '--abi', 'cp' + version.replace('.', ''), '--dest', str(wheels)]
            for platform in ['manylinux_2_34_', 'manylinux_2_28_', 'manylinux2014_']:
                command.extend(['--platform', platform + architecture])
            subprocess.run(command + PINS, check=True, stdout=subprocess.DEVNULL)
        lines = []
        for pin in PINS:
            package = pin.split('==')[0].lower().replace('-', '_')
            matches = [path for path in wheels.glob('*.whl') if path.name.lower().startswith(package + '-')]
            if not matches:
                raise ValueError('runtime wheel missing or ambiguous: ' + package)
            hashes = [' --hash=sha256:' + hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(matches)]
            lines.append(pin + ''.join(hashes))
        (root / 'requirements.lock').write_text('\n'.join(lines) + '\n')
        with tarfile.open(output, 'w:gz') as archive:
            for path in sorted(root.rglob('*')):
                if path.is_file():
                    archive.add(path, arcname=str(path.relative_to(root)), recursive=False)


if __name__ == '__main__':
    main()
