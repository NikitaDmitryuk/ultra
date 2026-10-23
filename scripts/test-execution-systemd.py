#!/usr/bin/env python3
"""Disposable Docker: real systemd deadlines, dispatcher death and containment.

Requires Docker's privileged private cgroup namespace, never host mounts/systemd.
The workload runner is synthetic; SSH readiness is covered by installer tests.
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
 if os.Geteuid()!=0 {state,e:=d.ExpectedLocalExecutionState();if e!=nil{panic(e)};if e=d.ConfigureLocalExecutionState(state);e!=nil{panic(e)}}
 os.WriteFile("/fixture/dispatcher.pid",[]byte(fmt.Sprint(os.Getpid())),0600)
 if os.Args[1]=="observe" { f,e:=d.InspectExecutionFence(); out:=map[string]any{"fence":f,"inspect_error":fmt.Sprint(e)};if f!=nil {out["reconcile_error"]=fmt.Sprint(d.ReconcileExecutionFence(*f))}; json.NewEncoder(os.Stdout).Encode(out);return }
 ctx,cancel:=signal.NotifyContext(context.Background(),syscall.SIGTERM);defer cancel()
 budget:=2*time.Second;if os.Args[1]=="cancel"||os.Args[1]=="child"||os.Args[1]=="success"{budget=20*time.Second};ctx,e:=d.WithExecutionTimeout(ctx,budget);if e!=nil{panic(e)}
 r,e:=d.RunLocal(ctx,"bootstrap",map[string]any{"all":map[string]any{}},map[string]any{},"/fixture/job","/usr/bin/python3","/fixture/runner")
 json.NewEncoder(os.Stdout).Encode(map[string]any{"receipt":r,"error":fmt.Sprint(e)})
 if e!=nil{os.Exit(1)}
}'''
RUNNER = '''#!/usr/bin/python3
import json,os,pathlib,subprocess,sys,time
root=pathlib.Path('/fixture');(root/'runner-started').write_text('yes')
if (root/'child-mode').exists() or (root/'success-mode').exists():
 if (root/'child-mode').exists():
  p=subprocess.Popen(['/usr/bin/sleep','30'],start_new_session=True)
  (root/'child.pid').write_text(str(p.pid))
 job=pathlib.Path(sys.argv[-1][1:]).parent
 (job/'result.json').write_text('{"verified":true}');(job/'result.json').chmod(0o600)
else: time.sleep(30)
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
    parser.add_argument('--scenario', choices=('timeout','crash','cancel','child',
        'user-success','user-timeout','user-crash','user-child'), action='append')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='.execution-fixture-', dir=ROOT) as generated:
        directory = Path(generated)
        (directory/'main.go').write_text(HELPER)
        helper = directory/'helper'
        run(['go','build','-o',str(helper),str(directory/'main.go')], env={**os.environ,'CGO_ENABLED':'0'})
        (directory/'Dockerfile').write_text('FROM ubuntu:24.04\nENV container=docker\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv libpam-systemd dbus dbus-user-session python3 python3-venv && rm -rf /var/lib/apt/lists/*\nSTOPSIGNAL SIGRTMIN+3\nCMD ["/sbin/init"]\n')
        image = 'ultra-execution-systemd-fixture'
        run(['docker','build','-q','-t',image,str(directory)])
        (directory/'runner').write_text(RUNNER)
        (directory/'runner').chmod(0o700)
        for scenario in (args.scenario or ('timeout','crash','cancel','child',
                                          'user-success','user-timeout','user-crash','user-child')):
            user_mode = scenario.startswith('user-')
            case = scenario.removeprefix('user-')
            name = 'ultra-execution-test-'+uuid.uuid4().hex[:12]
            run(['docker','run','-d','--name',name,'--network','none','--privileged','--cgroupns','private',
                 '--tmpfs','/run','--tmpfs','/run/lock','--tmpfs','/tmp',image])
            def command(*argv): return run(['docker','exec',name,*argv])
            def operator_command(*argv):
                prefix = ['docker','exec']
                if user_mode:
                    prefix += ['--user','1000','--env','XDG_RUNTIME_DIR=/run/user/1000']
                return run([*prefix,name,*argv])
            def manager(*argv):
                return operator_command('systemctl', *(['--user'] if user_mode else []), *argv)
            def exists(path): return subprocess.run(['docker','exec',name,'test','-e',path],capture_output=True).returncode==0
            try:
                wait(lambda: subprocess.run(['docker','exec',name,'systemctl','show','--property=Version','--value'],capture_output=True).returncode==0)
                command('mkdir','-m','700','/fixture')
                for filename in ('helper','runner'):
                    run(['docker','cp',str(directory/filename),name+':/fixture/'+filename])
                fence_root = '/var/lib/ultra-ansible'
                if user_mode:
                    account = command('getent','passwd','1000').split(':')
                    assert len(account)==7 and account[0]=='ubuntu' and account[2:4]==['1000','1000'] and account[5]=='/home/ubuntu', account
                    command('chown','-R','1000:1000','/fixture')
                    command('systemctl','start','dbus.service','systemd-logind.service')
                    command('loginctl','enable-linger','ubuntu')
                    try:
                        command('systemctl','start','user@1000.service')
                    except RuntimeError as error:
                        journal = command('journalctl','--unit=user@1000.service','--no-pager','-n','60')
                        raise RuntimeError(str(error) + '\nuser manager journal:\n' + journal) from error
                    wait(lambda: subprocess.run(['docker','exec','--user','1000','--env',
                        'XDG_RUNTIME_DIR=/run/user/1000',name,'systemctl','--user','show',
                        '--property=Version','--value'],capture_output=True).returncode==0)
                    fence_root = '/home/ubuntu/.local/state/ultra-ansible'
                if case=='child':command('touch','/fixture/child-mode')
                if case=='success':command('touch','/fixture/success-mode')
                prefix=['docker','exec']
                if user_mode:prefix+=['--user','1000','--env','XDG_RUNTIME_DIR=/run/user/1000']
                process=subprocess.Popen([*prefix,name,'/fixture/helper',case],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                def runner_started():
                    started = exists('/fixture/runner-started')
                    if not started and process.poll() is not None:
                        output, errors = process.communicate()
                        raise AssertionError((scenario, process.returncode, output, errors))
                    return started
                wait(runner_started)
                if case=='success':
                    output,errors=process.communicate(timeout=50)
                    assert process.returncode==0,(scenario,output,errors)
                    proof=json.loads(command('cat','/fixture/job/execution-containment.json'))
                    assert proof['schema']==2 and proof['uid']==1000 and proof['manager']=='user',proof
                    assert proof['control_group'].startswith('/user.slice/user-1000.slice/user@1000.service/app.slice/'),proof
                    assert exists('/fixture/job/execution-drain-'+proof['fence']['generation']+'.json')
                    assert not exists(fence_root+'/execution-fence.json')
                    assert json.loads(operator_command('/fixture/helper','observe'))['fence'] is None
                    print('isolated '+scenario+': passed',flush=True)
                    continue
                fence=json.loads(command('cat',fence_root+'/execution-fence.json'))
                unit='ultra-execution-'+fence['generation']+'.service'
                if case in ('timeout','crash'):
                    # Freeze the controller so its Python deadline cannot
                    # race the service manager's independently enforced one.
                    manager('kill','--kill-whom=main','--signal=STOP',unit)
                if case in ('crash','cancel'):
                    pid=command('cat','/fixture/dispatcher.pid')
                    command('kill','-KILL' if case=='crash' else '-TERM',pid)
                output,errors=process.communicate(timeout=50)
                assert process.returncode!=0,(scenario,output,errors)
                if case in ('timeout','crash'):
                    wait(lambda:'Result=timeout' in manager('show',unit,'--property=Result'))
                if case=='crash':
                    assert not exists('/fixture/job/execution-systemd-limit-'+fence['generation']+'.json')
                if case=='cancel':
                    receipt=json.loads(command('cat','/fixture/job/receipt.json'))
                    assert (receipt['state'],receipt['code'])==('running','interrupted'),receipt
                observed=json.loads(operator_command('/fixture/helper','observe'))
                assert observed['fence']==fence and observed['reconcile_error']!='<nil>',observed
                assert not exists('/fixture/job/execution-completion.json'),scenario
                if case in ('timeout','crash'):
                    assert exists('/fixture/job/execution-systemd-limit-'+fence['generation']+'.json')
                    assert observed['reconcile_error']=='execution_runtime_limit',observed
                if case=='child':
                    assert exists('/fixture/child.pid')
                    # A successful workload result alone cannot manufacture
                    # normal completion while its escaped descendant lives.
                    receipt=json.loads(command('cat','/fixture/job/receipt.json'))
                    assert receipt['state']=='succeeded',receipt
                assert exists(fence_root+'/execution-fence.json')
                print('isolated '+scenario+': passed',flush=True)
            finally:
                run(['docker','rm','-f',name])


if __name__=='__main__':
    main()
