import ast
import pathlib
import tempfile
import types
import unittest
from unittest.mock import patch

source=pathlib.Path(__file__).parents[1]/'deploy/setup-subscription-ingress.py'
remote=next(n.value.value for n in ast.walk(ast.parse(source.read_text())) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='remote' for t in n.targets))

class IngressSetupTests(unittest.TestCase):
    def execute(self, root, config, calls):
        def mapped(path):return root/str(path).lstrip('/')
        def run(args,**kwargs):
            calls.append(args)
            return types.SimpleNamespace(returncode=0,stdout='')
        with patch('subprocess.run',run):
            exec(remote.replace('P=pathlib.Path','P=mapped_path'),{'config':config,'mapped_path':mapped})
    def test_foreign_configuration_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);cfg=root/'etc/haproxy/haproxy.cfg';cfg.parent.mkdir(parents=True);cfg.write_text('foreign')
            calls=[]
            with self.assertRaisesRegex(ValueError,'foreign_haproxy_configuration'):self.execute(root,'managed',calls)
            self.assertEqual(cfg.read_text(),'foreign')
            self.assertEqual(len(calls),1) # Only the package inventory was read.
    def test_repeat_does_not_reload_or_change_configuration(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);cfg=root/'etc/haproxy/haproxy.cfg';cfg.parent.mkdir(parents=True);cfg.write_text('managed')
            calls=[]
            self.execute(root,'managed',calls)
            self.execute(root,'managed',calls)
            self.assertEqual(cfg.read_text(),'managed')
            self.assertNotIn(['systemctl','reload','haproxy'],calls)
            self.assertNotIn(['systemctl','restart','haproxy'],calls)

if __name__=='__main__':unittest.main()
