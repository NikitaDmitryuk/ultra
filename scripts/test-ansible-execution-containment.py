#!/usr/bin/env python3
"""Attest actual systemd identity; no unit-name-only production admission."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('containment',ROOT/'deploy/ansible/library/ultra_execution_containment.py')
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)


class Containment(unittest.TestCase):
    def setUp(self):
        self.generation='a'*32;self.unit='ultra-execution-'+self.generation+'.service'
        self.group='/system.slice/'+self.unit;self.pid=4242;self.job='/var/lib/ultra-ansible/fixture-job'
        self.exe=Path('/usr/bin/python3.12')
        self.argv=[str(self.exe),self.job+'/bundle/controller.py','--job',self.job,'--bundle',self.job+'/bundle','--executable','/opt/fixture/ansible-playbook']
        self.properties={'LoadState':'loaded','ActiveState':'active','ControlGroup':self.group,
            'KillMode':'control-group','Delegate':'no','User':'root','MainPID':str(self.pid),
            'FragmentPath':'/run/systemd/transient/'+self.unit,'ExecStart':'{ path='+str(self.exe)+' ; argv[]=fixed ; }'}
        self.uid='0 0 0 0'
        self.account_uid = 0

    def run_attestation(self):
        def text(path,*args,**kwargs):
            key=str(path)
            if key=='/proc/self/cgroup' or key==f'/proc/{self.pid}/cgroup':return '0::'+self.group+'\n'
            if key==f'/proc/{self.pid}/status':return 'Uid: '+self.uid+'\n'
            raise AssertionError(key)
        def raw(path,*args,**kwargs):
            self.assertEqual(str(path),f'/proc/{self.pid}/cmdline');return ('\0'.join(self.argv)+'\0').encode()
        result=subprocess.CompletedProcess([],0,stdout=''.join(k+'='+v+'\n' for k,v in self.properties.items()))
        with patch.object(Path,'read_text',text),patch.object(Path,'read_bytes',raw), \
             patch.object(Path,'resolve',lambda p,**kw:self.exe), \
             patch.object(C,'trusted',lambda p,**kw:Path(p)),patch.object(C.os,'getpid',return_value=self.pid), \
             patch.object(C.os,'geteuid',return_value=self.account_uid), \
             patch.object(C.os.path,'samefile',side_effect=lambda a,b:str(a)==str(b)), \
             patch.object(C.subprocess,'run',return_value=result):
            return C.require_containment(Path(self.job),self.generation)

    def test_exact_transient_job_is_accepted(self):
        self.assertEqual(self.run_attestation(),self.unit)

    def test_name_is_insufficient_without_systemd_ownership_and_control(self):
        for key,value in [('KillMode','process'),('Delegate','yes'),('User','nobody'),
                          ('ControlGroup','/foreign'),('LoadState','not-found'),('ActiveState','inactive'),
                          ('FragmentPath','/tmp/foreign.service'),('ExecStart','{ path=/bin/false ; }')]:
            with self.subTest(key=key):
                original=self.properties[key];self.properties[key]=value
                with self.assertRaises(ValueError):self.run_attestation()
                self.properties[key]=original

    def test_foreign_generation_process_and_job_are_rejected(self):
        self.generation='b'*32
        with self.assertRaises(ValueError):self.run_attestation()
        self.generation='a'*32;self.uid='1000 1000 1000 1000'
        with self.assertRaises(ValueError):self.run_attestation()
        self.uid='0 0 0 0';self.argv[3]='/foreign-job'
        with self.assertRaises(ValueError):self.run_attestation()

    def test_supervisor_requires_exact_current_request(self):
        self.unit='ultra-deploy-'+'a'*64+'.service';self.group='/system.slice/'+self.unit
        self.properties['ControlGroup']=self.group
        self.argv[1:]=['deploy-operation','run','--directory','/foreign-operation']
        with self.assertRaises((ValueError,AssertionError)):self.run_attestation()

    def completion_fixture(self, members, identity_change=False):
        unit = 'ultra-ansible-controller.service'
        group = '/system.slice/' + unit
        chain = {
            303: {'pid': 303, 'parent': 202, 'starttime': '30', 'group': group,
                  'executable_sha256': 'a' * 64, 'argv_sha256': 'b' * 64},
            202: {'pid': 202, 'parent': 101, 'starttime': '20', 'group': group,
                  'executable_sha256': 'c' * 64, 'argv_sha256': 'd' * 64},
            101: {'pid': 101, 'parent': 1, 'starttime': '10', 'group': group,
                  'executable_sha256': 'e' * 64, 'argv_sha256': 'f' * 64},
        }
        calls = 0
        def identity(pid):
            nonlocal calls
            calls += 1
            result = dict(chain[pid])
            if identity_change and calls > 3:
                result['starttime'] = 'reused'
            return result
        result = subprocess.CompletedProcess([], 0, stdout='MainPID=101\nControlGroup=' + group + '\nInvocationID=' + 'a' * 32 + '\n')
        with patch.object(C, 'require_containment', return_value=unit), \
             patch.object(C.os, 'getpid', return_value=303), \
             patch.object(C.os, 'geteuid', return_value=0), \
             patch.object(C.subprocess, 'run', return_value=result), \
             patch.object(C, 'process_identity', side_effect=identity), \
             patch.object(C, 'cgroup_processes', return_value=set(members)):
            return C.completion_containment(Path(self.job), {'generation': self.generation})

    def test_reused_unit_escaped_setsid_worker_prevents_completion_until_gone(self):
        # Escaping PGID does not escape cgroup. Only the actual ancestry is exempt.
        with self.assertRaisesRegex(ValueError, 'workers_live'):
            self.completion_fixture([101, 202, 303, 404])
        proof = self.completion_fixture([101, 202, 303])
        self.assertEqual(proof['mode'], 'reuse')
        self.assertEqual([member['pid'] for member in proof['chain']], [303, 202, 101])

    def test_census_rejects_pid_reuse_and_missing_ancestry(self):
        with self.assertRaises(ValueError):
            self.completion_fixture([101, 202, 303], identity_change=True)
        with self.assertRaises(ValueError):
            self.completion_fixture([101, 303])

    def test_real_system_executable_is_root_controlled(self):
        executable=Path(sys.executable).resolve()
        if all(member.lstat().st_uid==0 for member in [executable,*executable.parents]):
            self.assertEqual(C.trusted(executable),executable)
        else:
            with self.assertRaises(ValueError):C.trusted(executable)

    def test_current_unapproved_process_cannot_dispatch(self):
        with self.assertRaises(ValueError):C.require_containment(Path(self.job),self.generation)

    def test_user_manager_requires_exact_account_group_and_generation(self):
        account = C.pwd.getpwuid(os.geteuid())
        self.account_uid = os.geteuid()
        if self.account_uid == 0:
            self.skipTest('requires unprivileged account fixture')
        uid = str(self.account_uid)
        self.group = '/user.slice/user-' + uid + '.slice/user@' + uid + '.service/app.slice/' + self.unit
        self.properties.update(ControlGroup=self.group, User='', FragmentPath='/run/user/' + uid + '/systemd/transient/' + self.unit)
        self.uid = ' '.join([uid] * 4)
        expected = str(Path(account.pw_dir) / '.local/state/ultra-ansible')
        with patch.dict(C.os.environ, {'ULTRA_OPERATOR_STATE_DIRECTORY': expected}, clear=True):
            self.assertEqual(self.run_attestation(), self.unit)
            for key, value in [('ControlGroup', '/system.slice/' + self.unit), ('User', 'root'),
                               ('FragmentPath', '/run/systemd/transient/' + self.unit)]:
                original = self.properties[key]
                self.properties[key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    self.run_attestation()
                self.properties[key] = original
        with patch.dict(C.os.environ, {'ULTRA_OPERATOR_STATE_DIRECTORY': '/tmp/other-namespace'}, clear=True):
            with self.assertRaises(ValueError):
                self.run_attestation()


if __name__=='__main__':unittest.main()
