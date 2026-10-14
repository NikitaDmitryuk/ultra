#!/usr/bin/env python3
"""Use the actual pinned Ansible loader to test input types and template trust."""
import importlib.util
from pathlib import Path
from ansible.parsing.dataloader import DataLoader
from ansible.template import Templar, trust_as_template

source = Path(__file__).resolve().parents[1] / 'deploy/ansible/controller.py'
spec = importlib.util.spec_from_file_location('controller', source)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
values = {'mode': '0755', 'boolean_text': 'false', 'number_text': '123', 'null_text': 'null', 'number': 123,
          'boolean': False, 'nested': {'literal': "{{ lookup('pipe', 'false') }}", 'array': ['yes', '0x123', None, True]}}
loaded = DataLoader().load(module.unsafe_yaml(values))
assert loaded == values, 'unsafe YAML changed input values/types'
for key in ('mode', 'boolean_text', 'number_text', 'null_text'):
    assert isinstance(loaded[key], str), (key, type(loaded[key]))
templar = Templar(loader=DataLoader(), variables=loaded)
assert templar.template(trust_as_template('{{ nested.literal }}')) == values['nested']['literal'], 'nested input evaluated as template'
print('Actual Ansible input type and trust regressions passed')
