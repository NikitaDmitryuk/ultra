#!/usr/bin/env python3
"""Ownership journal regression; uses generated temporary files only."""
import importlib.util
import json
from pathlib import Path
import tempfile

source = Path(__file__).resolve().parents[1] / 'deploy/ansible/library/ultra_owned_file.py'
spec = importlib.util.spec_from_file_location('owned', source)
owned = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owned)
with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    target, receipt = root / 'site', root / 'managed.json'
    assert owned.apply(target, receipt, b'one', 0o644)
    assert not owned.apply(target, receipt, b'one', 0o644)
    target.write_bytes(b'foreign')
    try:
        owned.apply(target, receipt, b'two', 0o644)
        raise AssertionError('foreign file accepted')
    except ValueError:
        pass
    target.write_bytes(b'one')
    # Power loss after file activation but before ownership receipt commit.
    pending = receipt.with_name(receipt.name + '.pending')
    pending.write_text(json.dumps({'version': 1, 'path': str(target), 'before': owned.digest(b'one'), 'after': owned.digest(b'two')}))
    target.write_bytes(b'two')
    assert not owned.apply(target, receipt, b'two', 0o644)
    assert not pending.exists()
    assert json.loads(receipt.read_text())[str(target)] == owned.digest(b'two')
    target.write_bytes(b'foreign')
    pending.write_text(json.dumps({'version': 1, 'path': str(target), 'before': owned.digest(b'two'), 'after': owned.digest(b'three')}))
    try:
        owned.apply(target, receipt, b'three', 0o644)
        raise AssertionError('transaction drift accepted')
    except ValueError:
        pass
print('owned file transaction regressions passed')
