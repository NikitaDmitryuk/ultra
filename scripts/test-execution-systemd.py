#!/usr/bin/env python3
"""Disposable Docker: real systemd deadlines, dispatcher death and SSH retry.

Requires Docker's privileged private cgroup namespace, never host mounts/systemd.
The workload runner is synthetic; readiness uses pinned Ansible and real SSH.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
HELPER = r'''package main
import("context";"encoding/json";"fmt";"os";"os/signal";"syscall";"time"; d "github.com/NikitaDmitryuk/ultra/internal/deployansible")
func main(){
 os.WriteFile("/fixture/dispatcher.pid",[]byte(fmt.Sprint(os.Getpid())),0600)
 if os.Args[1]=="observe" { f,e:=d.InspectExecutionFence(); out:=map[string]any{"fence":f,"inspect_error":fmt.Sprint(e)};if f!=nil {out["reconcile_error"]=fmt.Sprint(d.ReconcileExecutionFence(*f))}; json.NewEncoder(os.Stdout).Encode(out);return }
 ctx,cancel:=signal.NotifyContext(context.Background(),syscall.SIGTERM);defer cancel()
 if os.Args[1]=="readiness" {raw,_:=os.ReadFile("/fixture/inventory.json");var inventory map[string]any;json.Unmarshal(raw,&inventory);e:=d.WaitUpgradeReadiness(ctx,inventory,"/fixture","/usr/bin/python3","/opt/runtime/bin/ansible-playbook","11111111-2222-3333-4444-555555555555",false,"/fixture");if e!=nil{fmt.Println(e);os.Exit(1)};return}
 budget:=2*time.Second;if os.Args[1]=="cancel"||os.Args[1]=="child"{budget=20*time.Second};ctx,e:=d.WithExecutionTimeout(ctx,budget);if e!=nil{panic(e)}
 r,e:=d.RunLocal(ctx,"bootstrap",map[string]any{"all":map[string]any{}},map[string]any{},"/fixture/job","/usr/bin/python3","/fixture/runner")
 json.NewEncoder(os.Stdout).Encode(map[string]any{"receipt":r,"error":fmt.Sprint(e)})
 if e!=nil{os.Exit(1)}
}'''
RUNNER = '''#!/usr/bin/python3
import json,os,pathlib,subprocess,sys,time
root=pathlib.Path('/fixture');(root/'runner-started').write_text('yes')
if (root/'child-mode').exists():
 p=subprocess.Popen(['/usr/bin/sleep','30'],start_new_session=True)
 (root/'child.pid').write_text(str(p.pid))
 job=pathlib.Path(sys.argv[-1][1:]).parent
 (job/'result.json').write_text('{"verified":true}');(job/'result.json').chmod(0o600)
else: time.sleep(30)
'''
PROXY = '''import pathlib,select,socket,struct,threading
listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('127.0.0.1',2223));listener.listen()
pathlib.Path('/fixture/proxy-ready').touch()
first=True
def forward(client):
 server=socket.create_connection(('127.0.0.1',2222))
 try:
  while True:
   for source in select.select([client,server],[],[],20)[0]:
    data=source.recv(65536)
    if not data:return
    (server if source is client else client).sendall(data)
 finally:client.close();server.close()
while True:
 client,_=listener.accept()
 if first:
  first=False;client.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));client.close();pathlib.Path('/fixture/first-reset').touch()
 else:threading.Thread(target=forward,args=(client,),daemon=True).start()
'''


def run(argv, **kwargs):
    result = subprocess.run(argv, text=True, capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{argv[0]} exit={result.returncode}: {result.stdout[-2000:]} {result.stderr[-2000:]}')
    return result.stdout.strip()


def wait(check, seconds=45):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return
        time.sleep(.1)
    raise AssertionError('isolated fixture deadline exceeded')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--scenario', choices=('timeout','crash','cancel','child','readiness'), action='append')
    args = parser.parse_args()
    runtime = args.runtime.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix='.execution-fixture-', dir=ROOT) as generated:
        directory = Path(generated)
        (directory/'main.go').write_text(HELPER)
        helper = directory/'helper'
        run(['go','build','-o',str(helper),str(directory/'main.go')], env={**os.environ,'CGO_ENABLED':'0'})
        (directory/'Dockerfile').write_text('FROM ubuntu:24.04\nENV container=docker\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv dbus openssh-server openssh-client python3 python3-venv && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd /root/.ssh && ssh-keygen -A\nSTOPSIGNAL SIGRTMIN+3\nCMD ["/sbin/init"]\n')
        image = 'ultra-execution-systemd-fixture'
        run(['docker','build','-q','-t',image,str(directory)])
        (directory/'runner').write_text(RUNNER)
        (directory/'runner').chmod(0o700)
        for scenario in (args.scenario or ('timeout','crash','cancel','child','readiness')):
            name = 'ultra-execution-test-'+uuid.uuid4().hex[:12]
            run(['docker','run','-d','--name',name,'--network','none','--privileged','--cgroupns','private',
                 '--tmpfs','/run','--tmpfs','/run/lock','--tmpfs','/tmp',image])
            def command(*argv): return run(['docker','exec',name,*argv])
            def exists(path): return subprocess.run(['docker','exec',name,'test','-e',path],capture_output=True).returncode==0
            try:
                wait(lambda: subprocess.run(['docker','exec',name,'systemctl','show','--property=Version','--value'],capture_output=True).returncode==0)
                command('mkdir','-m','700','/fixture')
                for filename in ('helper','runner'):
                    run(['docker','cp',str(directory/filename),name+':/fixture/'+filename])
                if scenario=='readiness':
                    run(['docker','cp',str(runtime),name+':/fixture/runtime.tar.gz'])
                    command('mkdir','/fixture/runtime-wheels')
                    command('tar','-xzf','/fixture/runtime.tar.gz','-C','/fixture/runtime-wheels')
                    command('python3','-m','venv','/opt/runtime')
                    command('/opt/runtime/bin/pip','install','--no-index','--require-hashes','--find-links=/fixture/runtime-wheels/wheels','-r','/fixture/runtime-wheels/requirements.lock')
                    command('ssh-keygen','-q','-t','ed25519','-N','','-f','/fixture/identity')
                    command('cp','/fixture/identity.pub','/root/.ssh/authorized_keys')
                    command('chmod','600','/root/.ssh/authorized_keys')
                    command('passwd','-d','root')
                    command('mkdir','-p','/run/sshd')
                    command('/usr/sbin/sshd','-p','2222','-o','PermitRootLogin=yes','-o','PasswordAuthentication=no','-o','UsePAM=no')
                    public = command('cat','/etc/ssh/ssh_host_ed25519_key.pub').split()
                    inventory={'all':{'children':{'bridge':{'hosts':{'bridge':{'ansible_host':'127.0.0.1','ansible_port':2223,'ansible_user':'root','ansible_ssh_private_key_file':'/fixture/identity','ansible_ssh_args':'-F /dev/null -o ControlMaster=no -o ControlPath=none','ansible_ssh_common_args':'-o StrictHostKeyChecking=yes -o UserKnownHostsFile=/fixture/pins'}}}}}}
                    values={'/fixture/inventory.json':inventory,'/var/lib/ultra-relay/recovery-reconcile-status.json':{'state':'ready','independent':True,'updated_at':time.time()},'/var/lib/ultra-recovery/last-success.json':{'snapshot_at':time.time()}}
                    command('python3','-c',"import json,pathlib,sys; values=json.loads(sys.argv[1]); [(pathlib.Path(p).parent.mkdir(parents=True,exist_ok=True),pathlib.Path(p).write_text(json.dumps(v)),pathlib.Path(p).chmod(0o600)) for p,v in values.items()]",json.dumps(values))
                    command('python3','-c',"import pathlib,sys;pathlib.Path('/fixture/pins').write_text(sys.argv[1])",'[127.0.0.1]:2223 '+public[0]+' '+public[1]+'\n')
                    command('python3','-c',"import pathlib,sys;pathlib.Path('/fixture/proxy.py').write_text(sys.argv[1])",PROXY)
                    run(['docker','exec','-d',name,'python3','/fixture/proxy.py'])
                    wait(lambda:exists('/fixture/proxy-ready'))
                    result=subprocess.run(['docker','exec',name,'/fixture/helper','readiness'],capture_output=True,text=True)
                    if result.returncode:
                        diagnostics=command('python3','-c',"import pathlib; print([p.read_text() for p in pathlib.Path('/fixture').glob('readiness-diagnostic-*.json')])")
                        raise AssertionError('real SSH readiness failed: '+result.stdout+' diagnostics='+diagnostics)
                    assert exists('/fixture/first-reset')
                    diagnostic=json.loads(command('python3','-c',"import pathlib; files=list(pathlib.Path('/fixture').glob('readiness-diagnostic-*.json')); assert len(files)==1; print(files[0].read_text())"))
                    assert diagnostic['code']=='ssh_connection_reset',diagnostic
                else:
                    if scenario=='child':command('touch','/fixture/child-mode')
                    process=subprocess.Popen(['docker','exec',name,'/fixture/helper',scenario],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    wait(lambda:exists('/fixture/runner-started'))
                    fence=json.loads(command('cat','/var/lib/ultra-ansible/execution-fence.json'))
                    unit='ultra-execution-'+fence['generation']+'.service'
                    if scenario in ('timeout','crash'):
                        # Freeze the controller so its Python deadline cannot
                        # race the service manager's independently enforced one.
                        command('systemctl','kill','--kill-whom=main','--signal=STOP',unit)
                    if scenario in ('crash','cancel'):
                        pid=command('cat','/fixture/dispatcher.pid')
                        command('kill','-KILL' if scenario=='crash' else '-TERM',pid)
                    output,errors=process.communicate(timeout=50)
                    assert process.returncode!=0,(scenario,output,errors)
                    if scenario in ('timeout','crash'):
                        wait(lambda:'Result=timeout' in command('systemctl','show',unit,'--property=Result'))
                    if scenario=='crash':
                        assert not exists('/fixture/job/execution-systemd-limit-'+fence['generation']+'.json')
                    if scenario=='cancel':
                        receipt=json.loads(command('cat','/fixture/job/receipt.json'))
                        assert (receipt['state'],receipt['code'])==('running','interrupted'),receipt
                    observed=json.loads(command('/fixture/helper','observe'))
                    assert observed['fence']==fence and observed['reconcile_error']!='<nil>',observed
                    assert not exists('/fixture/job/execution-completion.json'),scenario
                    if scenario in ('timeout','crash'):
                        assert exists('/fixture/job/execution-systemd-limit-'+fence['generation']+'.json')
                        assert observed['reconcile_error']=='execution_runtime_limit',observed
                    if scenario=='child':
                        assert exists('/fixture/child.pid')
                        # A successful workload result alone cannot manufacture
                        # normal completion while its escaped descendant lives.
                        receipt=json.loads(command('cat','/fixture/job/receipt.json'))
                        assert receipt['state']=='succeeded',receipt
                    assert exists('/var/lib/ultra-ansible/execution-fence.json')
                print('isolated '+scenario+': passed',flush=True)
            finally:
                run(['docker','rm','-f',name])


if __name__=='__main__':
    main()
