#!/usr/bin/env python3
"""Real disposable SSHD: dead client behind a TCP-preserving relay must drain."""
import json
import os
from pathlib import Path
import re
import selectors
import shlex
import signal
import socket
import subprocess
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]


def run(args, data=None, timeout=90):
    r = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    if r.returncode:
        raise RuntimeError('fixture command failed: ' + r.stderr.decode(errors='replace')[-2000:])
    return r.stdout


def constant(path, name):
    return re.search(r'const ' + name + r' = `(.*?)`', path.read_text(), re.S).group(1)


class Relay:
    """After freeze, ACK/read backend TCP but never answer SSH encrypted probes."""
    def __init__(self, backend):
        self.listener = socket.socket()
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.port = self.listener.getsockname()[1]
        self.backend = backend
        self.frozen = threading.Event()
        self.done = threading.Event()
        self.connected = threading.Event()
        self.thread = threading.Thread(target=self.forward, daemon=True)
        self.thread.start()

    def forward(self):
        sockets = []
        try:
            self.listener.settimeout(10)
            front, _ = self.listener.accept()
            back = socket.create_connection(('127.0.0.1', self.backend))
            sockets = [front, back]
            self.connected.set()
            with selectors.DefaultSelector() as poll:
                poll.register(front, selectors.EVENT_READ, back)
                poll.register(back, selectors.EVENT_READ, front)
                while not self.done.is_set():
                    for key, _ in poll.select(.05):
                        block = key.fileobj.recv(4096)
                        if not block:
                            poll.unregister(key.fileobj)
                            # Deliberately preserve the backend socket after
                            # client EOF: this reproduces the failed TCP proxy.
                            continue
                        if not self.frozen.is_set():
                            key.data.sendall(block)
                            time.sleep(.002)
        except (OSError, ValueError):
            if not self.done.is_set():
                self.done.set()
        finally:
            for item in sockets:
                item.close()

    def close(self):
        self.done.set()
        self.listener.close()
        self.thread.join(3)


def main():
    run(['docker', 'build', '-q', '-t', 'ultra-ansible-exit-fixture', str(ROOT / 'deploy/ansible/tests')], timeout=300)
    with tempfile.TemporaryDirectory(prefix='ultra-ssh-liveness-') as directory:
        directory = Path(directory)
        (directory / 'Dockerfile').write_text('FROM ultra-ansible-exit-fixture\nRUN apt-get update -q && apt-get install -y iproute2\nRUN sed -i \'s|^Subsystem[[:space:]].*|Subsystem sftp /usr/bin/setsid --fork --wait /usr/lib/openssh/sftp-server|\' /etc/ssh/sshd_config\n')
        run(['docker', 'build', '-q', '-t', 'ultra-replacement-ssh-fixture', str(directory)], timeout=300)
        key = directory / 'identity'
        run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)])
        container = run(['docker', 'run', '-d', '--cap-add=SYS_PTRACE', '-p', '127.0.0.1::22', 'ultra-replacement-ssh-fixture']).decode().strip()
        try:
            run(['docker', 'cp', str(key.with_suffix('.pub')), container + ':/root/.ssh/authorized_keys'])
            run(['docker', 'exec', container, 'chown', 'root:root', '/root/.ssh/authorized_keys'])
            run(['docker', 'exec', container, 'chmod', '600', '/root/.ssh/authorized_keys'])
            public = run(['docker', 'exec', container, 'cat', '/etc/ssh/ssh_host_ed25519_key.pub']).decode().split()
            pins = directory / 'pins'
            pins.write_text('fixture-server ' + public[0] + ' ' + public[1] + '\n')
            port = int(run(['docker', 'port', container, '22/tcp']).decode().split(':')[-1])
            base = ['-F', '/dev/null', '-i', str(key), '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                    '-o', 'UserKnownHostsFile=' + str(pins), '-o', 'HostKeyAlias=fixture-server',
                    '-o', 'ControlMaster=no', '-o', 'ControlPath=none', '-o', 'ConnectTimeout=5']

            def ssh(program):
                return run(['ssh'] + base + ['-p', str(port), 'root@127.0.0.1', 'python3 -'], program.encode(), timeout=55)

            definitions = constant(ROOT / 'cmd/ultra-install/production_replace_remote.go', 'replacementSessionCensusDefinitions')
            census = definitions + "\ntry:\n require_sessions_quiescent(os.getpid())\n print(json.dumps({'quiescent':True}))\nexcept ValueError as e:\n print(json.dumps({'quiescent':False,'code':str(e),'offender':getattr(e,'offender',None)}))\n"
            snapshot = definitions + "\ntry:\n validate_sessions(read_sessions(),os.getpid())\n print(json.dumps({'quiescent':True}))\nexcept ValueError as e:\n print(json.dumps({'quiescent':False,'code':str(e),'offender':getattr(e,'offender',None)}))\n"
            source = directory / 'payload'
            source.write_bytes(os.urandom(8 * 1024 * 1024))

            def orphan():
                relay = Relay(port)
                target = '/tmp/fixture-partial-' + uuid.uuid4().hex
                client = subprocess.Popen(['sftp', '-b', '-'] + base + ['-P', str(relay.port), 'root@127.0.0.1'],
                                          stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                          start_new_session=True)
                try:
                    client.stdin.write(('put ' + shlex.quote(str(source)) + ' ' + target + '\n').encode())
                    client.stdin.flush()
                    assert relay.connected.wait(5), 'relay did not connect'
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        probe = """import os,json,pathlib
p=pathlib.Path(TARGET)
result={'bytes':p.stat().st_size if p.exists() else 0,'separate_sid_root_sftp':False,'sftp_metadata':[],'server_comms':[]}
for row in pathlib.Path('/proc').iterdir():
 if not row.name.isdigit():continue
 try:
  comm=(row/'comm').read_text().strip()
  if 'sftp'in comm or comm=='setsid':result['server_comms'].append(comm)
  found=False
  for fd in (row/'fd').iterdir():
   try:
    if os.readlink(fd)==str(p):found=True
   except OSError:pass
  if not found:continue
  fields=(row/'stat').read_text().split(') ',1)[1].split()
  uids=next(x for x in (row/'status').read_text().splitlines()if x.startswith('Uid:')).split()[1:]
  result['sftp_metadata'].append({'pid':int(row.name),'ppid':int(fields[1]),'sid':os.getsid(int(row.name)),'parent_sid':os.getsid(int(fields[1])),'uids':uids})
  result['separate_sid_root_sftp']=all(v=='0'for v in uids)and os.getsid(int(row.name))!=os.getsid(int(fields[1]))
 except OSError:pass
print(json.dumps(result))
""".replace('TARGET',repr(target))
                        observed = json.loads(ssh(probe))
                        if observed['bytes'] > 0:
                            assert observed['separate_sid_root_sftp'], 'fixture did not create a separate-SID root SFTP descendant: ' + str(observed)
                            break
                        time.sleep(.05)
                    else:
                        raise AssertionError('SFTP never opened the partial upload')
                    relay.frozen.set()
                    os.killpg(client.pid, signal.SIGKILL)
                    client.wait(5)
                    client.stdin.close()
                    assert not relay.done.is_set(), 'backend TCP closed instead of remaining held'
                    return relay, target
                except BaseException:
                    if client.poll() is None:
                        os.killpg(client.pid, signal.SIGKILL)
                        client.wait(5)
                    relay.close()
                    raise

            relay, target = orphan()
            try:
                assert not json.loads(ssh(snapshot))['quiescent'], 'baseline lost the half-open session'
                time.sleep(2)
                assert not json.loads(ssh(snapshot))['quiescent'], 'baseline unexpectedly expired'
            finally:
                relay.close()
            assert json.loads(ssh(census))['quiescent'], 'baseline cleanup did not drain'
            ssh('from pathlib import Path; Path(' + repr(target) + ').unlink(missing_ok=True)')

            # Exercise the actual native program, real Ubuntu Include layout,
            # real sshd -t/-T parsing and a real listener reload. This shim only
            # adapts service metadata to a container whose PID1 is the SSH listener.
            # No ExecReload adapter exists: activation must signal the bound PID.
            shim = '#!/usr/bin/python3\nimport sys\nfrom pathlib import Path\nif sys.argv[1]=="show":\n p=Path("/tmp/fixture-main-pid");pid=p.read_text().strip()if p.exists()else"1"\n print("ActiveState=active\\nMainPID="+pid+"\\nExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D -e ; ignore_errors=no ; }")\nelse:sys.exit(1)\n'
            ssh("from pathlib import Path; p=Path('/usr/local/bin/systemctl'); p.write_text(" + repr(shim) + "); p.chmod(0o755)")
            policy = constant(ROOT / 'cmd/ultra-install/production_replace_ssh.go', 'replacementSSHLivenessDefinitions')
            full = (ROOT / 'cmd/ultra-install/production_replace_ssh.go').read_text()
            suffix = re.search(r'const replacementSSHLivenessProgram = replacementSSHLivenessDefinitions \+ `(.*?)`', full, re.S).group(1)
            program = policy + "\nsys.argv=['fixture','bridge','192.0.2.254']\n" + suffix
            def policy_failure(expected):
                result = subprocess.run(['ssh'] + base + ['-p', str(port), 'root@127.0.0.1', 'python3 -'],
                                        input=program.encode(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=55)
                receipt=json.loads(result.stdout)
                assert result.returncode != 0 and not receipt['verified'] and receipt['code']==expected, ('unexpected policy result',receipt)

            def fixture_python(code):
                return run(['docker', 'exec', '-i', container, 'python3', '-'], code.encode())

            fixture_python("from pathlib import Path; p=Path('/etc/ssh/sshd_config'); Path('/tmp/sshd-before').write_bytes(p.read_bytes()); extra=bytes([10])+b'Match User root'+bytes([10])+b'ClientAliveInterval 99'+bytes([10]); p.write_bytes(p.read_bytes()+extra)")
            policy_failure('replacement_ssh_liveness_conflict')
            fixture_python("from pathlib import Path; p=Path('/etc/ssh/sshd_config'); before=Path('/tmp/sshd-before').read_bytes(); extra=bytes([10])+b'Match User root'+bytes([10])+b'ClientAliveInterval 99'+bytes([10]); assert p.read_bytes()==before+extra; assert not Path('/etc/ssh/ultra-root-liveness.conf').exists(); p.write_bytes(before)")
            # Bind the *actual* listener, not just the default config on disk.
            # The shim still advertises a stock unit; real custom startup args
            # must independently reject before writing either managed file.
            for extra in (['-f', '/etc/ssh/sshd_config', '-p', '2222'], ['-o', 'Port=2222']):
                fixture_python("import subprocess,pathlib,time; p=subprocess.Popen(['/usr/sbin/sshd','-D','-e']+" + repr(extra) + ",stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); pathlib.Path('/tmp/fixture-main-pid').write_text(str(p.pid)); time.sleep(.2); assert p.poll()is None")
                try:
                    policy_failure('replacement_ssh_listener_args_unsupported')
                    fixture_python("from pathlib import Path; assert Path('/etc/ssh/sshd_config').read_bytes()==Path('/tmp/sshd-before').read_bytes(); assert not Path('/etc/ssh/ultra-root-liveness.conf').exists()")
                finally:
                    fixture_python("import os,signal; from pathlib import Path; p=Path('/tmp/fixture-main-pid'); os.kill(int(p.read_text()),signal.SIGTERM); p.unlink()")
            # Publish the exact owned disk pair without reloading the existing
            # 0/3 listener: simulate a crash at the final activation boundary.
            fixture_python(policy + "\nmain=Path('/etc/ssh/sshd_config');main.write_bytes(main.read_bytes()+BLOCK);Path('/etc/ssh/ultra-root-liveness.conf').write_bytes(POLICY)\n")
            assert json.loads(ssh(program))['verified'], 'interrupted activation was not completed'
            assert json.loads(ssh(program))['verified'], 'repeat was not idempotent'
            relay, target = orphan()
            try:
                assert not json.loads(ssh(snapshot))['quiescent'], 'policy fixture did not start an orphan'
                started = time.monotonic()
                observed = json.loads(ssh(census))
                assert observed['quiescent'], 'fresh replacement remained blocked after client death: ' + str(observed)
                assert time.monotonic() - started < 40, 'census exceeded its deadline'
                assert not relay.done.is_set(), 'proxy rather than sshd closed backend'
            finally:
                relay.close()
            ssh('from pathlib import Path; Path(' + repr(target) + ').unlink(missing_ok=True)')

            live = subprocess.Popen(['ssh'] + base + ['-p', str(port), 'root@127.0.0.1', 'sleep 60'],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                time.sleep(.5)
                assert not json.loads(ssh(snapshot))['quiescent'], 'responsive foreign SSH was accepted'
            finally:
                os.killpg(live.pid, signal.SIGKILL)
                live.wait(5)
            assert json.loads(ssh(census))['quiescent'], 'responsive fixture cleanup did not drain'
            print('Real SSH liveness: baseline blocked; TCP-preserving orphan drained; next full census passed; live foreign SSH blocked; root-only config verified; interrupted activation completed; custom listener args rejected')
        finally:
            run(['docker', 'rm', '-f', container])


if __name__ == '__main__':
    main()
