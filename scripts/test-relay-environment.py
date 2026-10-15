#!/usr/bin/env python3
"""Remote diagnostic projection keeps systemd override order without executing values."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

source = Path(__file__).with_name('relay-environment.py')
spec = importlib.util.spec_from_file_location('relay_environment', source)
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)

class Environment(unittest.TestCase):
    def test_file_overrides_directive_and_literal_values_are_not_executed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'environment'
            path.write_text('ULTRA_RELAY_ADMIN_TOKEN="literal; $(not-executed)"\n')
            def run(*args, **kwargs):
                value = 'ULTRA_RELAY_ADMIN_TOKEN=old' if 'Environment' in args else str(path) + ' (ignore_errors=no)'
                return SimpleNamespace(stdout=value)
            with patch.object(helper, 'run', side_effect=run):
                self.assertEqual(helper.environment()['ULTRA_RELAY_ADMIN_TOKEN'], 'literal; $(not-executed)')

if __name__ == '__main__':
    unittest.main()
