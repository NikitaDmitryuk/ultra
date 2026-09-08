import importlib.util
import pathlib
import subprocess
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('ingress_ssh',pathlib.Path(__file__).parents[1]/'deploy/setup-subscription-ingress-ssh.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class SSHIngressTests(unittest.TestCase):
    def prepare(self, folder):
        root=pathlib.Path(folder);nginx=root/'etc/nginx';nginx.mkdir(parents=True)
        (nginx/'nginx.conf').write_text('stream { include /etc/nginx/stream.d/*.conf; }')
        for name,(_,legacy) in m.configurations('192.0.2.1','bot.example').items():
            p=nginx/name;p.parent.mkdir(exist_ok=True);p.write_text(legacy)
        return root
    def test_adopt_existing_then_repeat_without_reload(self):
        with tempfile.TemporaryDirectory() as folder:
            root=self.prepare(folder);calls=[]
            run=lambda args,**kwargs:calls.append(args)
            m.install('192.0.2.1','bot.example',root,run)
            self.assertEqual(calls.count(['systemctl','reload','nginx']),1)
            calls.clear();m.install('192.0.2.1','bot.example',root,run)
            self.assertNotIn(['systemctl','reload','nginx'],calls)
            for name,(expected,_) in m.configurations('192.0.2.1','bot.example').items():self.assertEqual((root/'etc/nginx'/name).read_text(),expected)
    def test_foreign_configuration_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            root=self.prepare(folder);p=root/'etc/nginx/stream.d/bot-proxy.conf';p.write_text('foreign');calls=[]
            with self.assertRaisesRegex(ValueError,'foreign_nginx'):m.install('192.0.2.1','bot.example',root,lambda args,**kw:calls.append(args))
            self.assertEqual(p.read_text(),'foreign');self.assertEqual(calls,[])
    def test_failed_validation_restores_original(self):
        with tempfile.TemporaryDirectory() as folder:
            root=self.prepare(folder);before={p:p.read_bytes() for p in (root/'etc/nginx').rglob('*.conf')};calls=[]
            def run(args,**kw):
                calls.append(args)
                if len(calls)==1:raise subprocess.CalledProcessError(1,args)
            with self.assertRaisesRegex(RuntimeError,'previous_restored'):m.install('192.0.2.1','bot.example',root,run)
            for p,data in before.items():self.assertEqual(p.read_bytes(),data)
            self.assertFalse((root/'etc/nginx/ultra-ingress.sha256.json').exists())
    def test_failed_reload_restores_original(self):
        with tempfile.TemporaryDirectory() as folder:
            root=self.prepare(folder);before={p:p.read_bytes() for p in (root/'etc/nginx').rglob('*.conf')};calls=[]
            def run(args,**kw):
                calls.append(args)
                if len(calls)==2:raise subprocess.CalledProcessError(1,args)
            with self.assertRaisesRegex(RuntimeError,'previous_restored'):m.install('192.0.2.1','bot.example',root,run)
            for p,data in before.items():self.assertEqual(p.read_bytes(),data)
            self.assertEqual(calls.count(['systemctl','reload','nginx']),2)
    def test_ssh_mode_does_not_send_vultr_code(self):
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);config=root/'install.config'
            config.write_text('BRIDGE=192.0.2.1\nBOT_INGRESS_IP=192.0.2.2\nBOT_DOMAIN=bot.example\nBOT_INGRESS_MODE=ssh\nSSH_USER=root\n')
            ssh=root/'ssh';ssh.write_text('#!/bin/sh\ncat\n');ssh.chmod(0o755)
            import os
            env=dict(os.environ,ULTRA_INSTALL_CONFIG=str(config),PATH=str(root)+':'+os.environ['PATH'])
            result=subprocess.run(['bash',str(pathlib.Path(__file__).with_name('setup-subscription-ingress.sh'))],env=env,text=True,capture_output=True,check=True)
            self.assertIn('def install(',result.stdout);self.assertNotIn('api.vultr.com',result.stdout);self.assertNotIn('ULTRA_VULTR_KEY_FILE',result.stdout)

if __name__=='__main__':unittest.main()
