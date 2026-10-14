import pathlib
import subprocess
import tempfile
import unittest


class SSHIngressTests(unittest.TestCase):
    def test_wrapper_uses_common_cli_without_ssh_or_secret_projection(self):
        import json
        import os
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder);(root/'scripts').mkdir()
            wrapper=root/'scripts/setup-subscription-ingress.sh'
            wrapper.write_bytes(pathlib.Path(__file__).with_name('setup-subscription-ingress.sh').read_bytes())
            config=root/'install.config';config.write_text('ULTRA_VULTR_KEY_FILE=private-should-not-be-projected\n')
            binary=root/'ultra-install';binary.write_text('#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n');binary.chmod(0o755)
            marker=root/'ssh-used';ssh=root/'ssh';ssh.write_text('#!/bin/sh\ntouch '+str(marker)+'\nexit 99\n');ssh.chmod(0o755)
            env=dict(os.environ,ULTRA_INSTALL_CONFIG=str(config),PATH=str(root)+':'+os.environ['PATH'])
            result=subprocess.run(['bash',str(wrapper)],env=env,text=True,capture_output=True,check=True)
            self.assertEqual(json.loads(result.stdout),['ingress','--config',str(config),'--action','activate'])
            self.assertFalse(marker.exists())
            self.assertNotIn('private-should-not-be-projected',result.stdout)
            forward= pathlib.Path(__file__).resolve().parents[1]/'deploy/ansible/roles/forward_ingress'
            for source in forward.rglob('*'):
                if source.is_file():
                    text=source.read_text();self.assertNotIn('ultra_dns_api_key',text);self.assertNotIn('ULTRA_VULTR_KEY_FILE',text)


if __name__ == "__main__":
    unittest.main()
