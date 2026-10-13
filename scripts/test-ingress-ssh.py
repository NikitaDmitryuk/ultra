import importlib.util
import pathlib
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('ingress_ssh',pathlib.Path(__file__).parents[1]/'deploy/setup-subscription-ingress-ssh.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

class SSHIngressTests(unittest.TestCase):
    def setUp(self):
        self.listener_patch = patch.object(m, 'wait_listeners')
        self.listener_probe = self.listener_patch.start()
        self.addCleanup(self.listener_patch.stop)

    def test_listener_probe_checks_all_ports_and_bounds_failure(self):
        self.listener_patch.stop()
        with patch.object(m.socket, 'create_connection') as connect:
            m.wait_listeners()
            self.assertEqual([call.args[0] for call in connect.call_args_list],
                             [('127.0.0.1', 80), ('127.0.0.1', 443), ('127.0.0.1', 8444)])
        with patch.object(m.socket, 'create_connection', side_effect=ConnectionRefusedError), patch.object(m.time, 'monotonic', side_effect=[0, 16]):
            with self.assertRaisesRegex(RuntimeError, 'listeners_unavailable'):
                m.wait_listeners()

    def test_async_reload_failure_is_not_ready_and_repeat_repairs(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.prepare(folder)
            for name, (desired, _) in m.configurations('192.0.2.1', 'bot.example').items():
                (root/'etc/nginx'/name).write_text(desired)
            calls = []
            self.listener_probe.side_effect = RuntimeError('ingress_listeners_unavailable')
            with self.assertRaisesRegex(RuntimeError, 'previous_restored'):
                m.install('192.0.2.1', 'bot.example', root, lambda args, **kw: calls.append(args))
            self.assertFalse((root/'etc/nginx/ultra-ingress.sha256.json').exists())
            calls.clear()
            self.listener_probe.side_effect = None
            m.install('192.0.2.1', 'bot.example', root, lambda args, **kw: calls.append(args))
            self.assertIn(['systemctl', 'reload', 'nginx'], calls)
            self.assertTrue((root/'etc/nginx/ultra-ingress.sha256.json').exists())

    def prepare(self, folder):
        root=pathlib.Path(folder);nginx=root/'etc/nginx';nginx.mkdir(parents=True)
        (nginx/'nginx.conf').write_text('stream { include /etc/nginx/stream.d/*.conf; }')
        for name,(_,legacy) in m.configurations('192.0.2.1','bot.example').items():
            p=nginx/name;p.parent.mkdir(exist_ok=True);p.write_text(legacy)
        return root
    def test_clean_forward_include_has_stream_context(self):
        original='events {}\nhttp { include /etc/nginx/conf.d/*.conf; }\n'
        for source in (original, original+'\ninclude /etc/nginx/stream.d/*.conf;\n'):
            rendered=m.forward_main(source)
            self.assertIn('stream {\n    include /etc/nginx/stream.d/*.conf;\n}',rendered)
            self.assertEqual(m.forward_main(rendered),rendered)
        existing='events {}\nstream { include /etc/nginx/stream.d/*.conf; }\n'
        self.assertEqual(m.forward_main(existing),existing)

    def test_adopt_existing_then_repeat_reloads_owned_configuration(self):
        with tempfile.TemporaryDirectory() as folder:
            root=self.prepare(folder);calls=[]
            run=lambda args,**kwargs:calls.append(args)
            m.install('192.0.2.1','bot.example',root,run)
            self.assertEqual(calls.count(['systemctl','reload','nginx']),1)
            calls.clear();m.install('192.0.2.1','bot.example',root,run)
            self.assertIn(['systemctl','reload','nginx'],calls)
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
