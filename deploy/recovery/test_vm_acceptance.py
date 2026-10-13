import hashlib
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest import mock
import vm_acceptance


class GenerationReceipt(unittest.TestCase):
    def test_payload_helpers_import_without_restore_modules_installed_in_product(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name,data in vm_acceptance.fixture_helper_sources().items():
                (root/name).write_bytes(data)
            # The product installs recovery.py, but not operator-only restore modules.
            (root/'recovery.py').write_bytes(Path(vm_acceptance.__file__).with_name('recovery.py').read_bytes())
            code='import runpy,sys;sys.path.insert(0,sys.argv[1]);v=runpy.run_path(sys.argv[1]+"/acceptance.py");assert callable(v["seed"])'
            subprocess.run([sys.executable,'-I','-c',code,str(root)],check=True,capture_output=True)

    def test_fetches_confirmed_receiver_pair_and_verifies_before_writing(self):
        topology={'synthetic_only':True,'nodes':{'us':'198.18.0.12'}}
        data={'backup':b'encrypted-state','artifact':b'encrypted-artifacts'}
        receipt={'destinations':['root@198.18.0.12'],'backup_name':'backup-123-'+('a'*32)+'.age','artifact_name':'artifact-'+('b'*64)+'.age'}
        for kind,value in data.items():receipt[kind+'_sha256']=hashlib.sha256(value).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            destination=Path(temporary)/'generation'
            with mock.patch.object(vm_acceptance,'ssh',side_effect=[data['backup'],data['artifact']]) as ssh:
                result=vm_acceptance.fetch_generation(topology,receipt,destination)
            self.assertEqual(result.read_bytes(),data['backup'])
            self.assertTrue(all(call.args[1]=='198.18.0.12' for call in ssh.call_args_list))
            self.assertEqual((destination/receipt['artifact_name']).read_bytes(),data['artifact'])
            with mock.patch.object(vm_acceptance,'ssh',side_effect=[data['backup'],b'tampered']):
                with self.assertRaisesRegex(ValueError,'ciphertext_mismatch'):
                    vm_acceptance.fetch_generation(topology,receipt,Path(temporary)/'invalid')
            self.assertFalse((Path(temporary)/'invalid').exists())
            with mock.patch.object(vm_acceptance,'ssh') as ssh:
                with self.assertRaisesRegex(ValueError,'confirmed_independent'):
                    vm_acceptance.fetch_generation(topology,{**receipt,'destinations':['root@198.18.0.11']},destination)
                ssh.assert_not_called()
