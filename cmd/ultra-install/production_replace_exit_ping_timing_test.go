package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestReplacementPingPublicationRealRefreshSchedule(t *testing.T) {
	bot, err := os.ReadFile("../../internal/bot/subscription_cache.go")
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(bot), "func (b *Bot) StartSubscriptionCacheWorker")
	if start < 0 || !strings.Contains(string(bot[start:]), "time.NewTicker(30 * time.Second)") ||
		!strings.Contains(string(bot[start:]), "context.WithTimeout(ctx, 15*time.Second)") {
		t.Fatal("refresh schedule changed; revalidate publication budget")
	}
	botUnit, err := os.ReadFile("../../deploy/ansible/roles/bot/templates/ultra-bot.service.j2")
	if err != nil {
		t.Fatal(err)
	}
	relayUnit, err := os.ReadFile("../../deploy/ansible/roles/relay/templates/ultra-relay.service.j2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(botUnit), "TimeoutStopSec=20s") || strings.Contains(string(relayUnit), "TimeoutStopSec=") {
		t.Fatal("service stop deadlines changed; revalidate worker budgets")
	}
	program, _ := json.Marshal(replacementPingPublicationProgram)
	fixture := `import json,sys,types
ns={'__name__':'fixture'};exec(json.loads(sys.argv[1]),ns)
clock=[0.];commands=[]
ns['time'].monotonic=lambda:clock[0]
ns['time'].sleep=lambda seconds:clock.__setitem__(0,clock[0]+seconds)
def service(name):commands.append(name)
ns['service']=service
# A late first refresh begins after 4s, fails after its full 15s timeout,
# and the real worker's 30s ticker retries; that request may use another 15s.
confirmed_at=4+30+15
class Cache:
 def exists(self):return clock[0]>=confirmed_at
 def is_symlink(self):return False
 def stat(self):return types.SimpleNamespace(st_mtime=100.)
 def read_text(self):return json.dumps({'version':1,'happ_exit_ping':True})
ns['Path']=lambda _:Cache()
ns['cache'](True,100.)
assert confirmed_at<=clock[0]<ns['CACHE_SECONDS'] and commands==['ultra-bot.service']
# Restart readiness polls are read-only drain barriers, with no repeated restart.
clock[0]=0.;commands.clear()
def run(args,**kwargs):
 commands.append(args)
 assert args[-1]=='ready' and 0<kwargs['timeout']<=28
 return types.SimpleNamespace(returncode=0 if clock[0]>=30 else 1)
ns['subprocess'].run=run
ns['ready']('a'*64)
assert 30<=clock[0]<ns['READY_SECONDS']
clock[0]=0.;ns['subprocess'].run=lambda *args,**kwargs:types.SimpleNamespace(returncode=1)
failed=False
try:ns['ready']('a'*64)
except ValueError as e:failed=True;assert str(e)=='exit_ping_admin_api_not_ready'
assert failed and clock[0]==ns['READY_SECONDS']
# Each restart happens once; deadline includes the unit's stop timeout.
timeouts=[]
ns['subprocess'].run=lambda args,**kwargs:timeouts.append(kwargs['timeout']) or types.SimpleNamespace(returncode=0)
fresh={'__name__':'fixture'};exec(json.loads(sys.argv[1]),fresh)
fresh['service']('ultra-relay.service');fresh['service']('ultra-bot.service')
assert timeouts==[95,3,25,3]
forward=95+3+35+25+3+50
assert forward+15<240 and 95+3+15<120
`
	command := exec.Command("python3", "-c", fixture, string(program))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("refresh/readiness timing %v: %s", err, out)
	}
	if replacementPingPublicationWait < 480*time.Second+20*time.Second || replacementPingExitWait < 270*time.Second+20*time.Second {
		t.Fatal("observation cannot cover runtime and independent recovery")
	}
	exitProgram, _ := json.Marshal(replacementPingExitProgram)
	exitFixture := `import json,sys,types
ns={'__name__':'fixture'};exec(json.loads(sys.argv[1]),ns)
timeouts=[]
ns['subprocess'].run=lambda args,**kwargs:timeouts.append(kwargs['timeout']) or types.SimpleNamespace(returncode=0)
ns['service']('restart');ns['service']('is-active','--quiet')
assert timeouts==[95,3]
assert 3+5+6+10+95+.5+6+5+15<150 # Host/pin, checks, restart, postcheck, durable IO margin.
assert 95+3+15<120 # Independent recovery must have its own full restart/IO budget.
`
	command = exec.Command("python3", "-c", exitFixture, string(exitProgram))
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("retained worker timing %v: %s", err, out)
	}
}

func TestReplacementPingCancelledQueuedWorkersCannotApply(t *testing.T) {
	exit, _ := json.Marshal(replacementPingExitProgram)
	publication, _ := json.Marshal(replacementPingPublicationProgram)
	fixture := `import json,sys
from pathlib import Path
root=Path(sys.argv[3]);d=root/('a'*64);d.mkdir(mode=0o700)
ns={'__name__':'fixture'};exec(json.loads(sys.argv[1]),ns)
ns['regular']=lambda p:Path(p)
(d/'request.json').write_text(json.dumps({'node':{}}));(d/'cancelled').write_text('cancelled')
failed=False
try:ns['apply'](d,root/'binary',root/'spec')
except ValueError as e:failed=True;assert str(e)=='exit_ping_transaction_cancelled'
assert failed and not (root/'binary').exists() and not (d/'receipt.json').exists()
source=json.loads(sys.argv[2]).replace('/var/lib/ultra-replacement-ping',str(root))
ns={'__name__':'fixture'};exec(source,ns)
ns['os'].geteuid=lambda:0;ns['fcntl'].flock=lambda *args:None
request=d/'publication-publish.json';request.write_text(json.dumps({'binding':'a'*64,'mode':'publish','bot_enabled':True}))
(d/'cancelled-publish').write_text('cancelled');ns['sys'].argv=['worker','apply',str(request)]
failed=False
try:ns['main']()
except ValueError as e:failed=True;assert str(e)=='exit_ping_publication_cancelled'
assert failed and not (d/'publication-publish-receipt.json').exists()
`
	command := exec.Command("python3", "-c", fixture, string(exit), string(publication), t.TempDir())
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("cancelled worker fixture %v: %s", err, out)
	}
}

func TestReplacementPingTerminalObservation(t *testing.T) {
	binding := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name   string
		states []replacementPingOperationState
		valid  bool
	}{
		{"started then terminal", []replacementPingOperationState{{Binding: binding, State: "running"}, {Binding: binding, State: "succeeded", Verified: true}}, true},
		{"terminal failure", []replacementPingOperationState{{Binding: binding, State: "running"}, {Binding: binding, State: "failed"}}, false},
		{"missing proof", []replacementPingOperationState{{Binding: binding, State: "succeeded"}}, false},
		{"different operation", []replacementPingOperationState{{Binding: strings.Repeat("b", 64), State: "succeeded", Verified: true}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i := 0
			pauses := 0
			_, err := waitReplacementPingOperation(context.Background(), binding, func(context.Context) ([]byte, error) {
				if i >= len(tc.states) {
					t.Fatal("extra observation")
				}
				raw, _ := json.Marshal(tc.states[i])
				i++
				return raw, nil
			}, func(context.Context) error { pauses++; return nil })
			if (err == nil) != tc.valid {
				t.Fatalf("terminal result %v", err)
			}
			if i != len(tc.states) || pauses != len(tc.states)-1 {
				t.Fatal("unexpected poll sequence")
			}
		})
	}
	calls := 0
	_, err := waitReplacementPingOperation(
		context.Background(),
		binding,
		func(context.Context) ([]byte, error) { calls++; return nil, errors.New("transport") },
		func(context.Context) error { t.Fatal("uncertain operation retried"); return nil },
	)
	if err == nil || calls != 1 {
		t.Fatal("transport uncertainty advanced operation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = waitReplacementPingOperation(
		ctx,
		binding,
		func(context.Context) ([]byte, error) { t.Fatal("cancelled operation observed"); return nil, nil },
		func(context.Context) error { return nil },
	)
	if err == nil {
		t.Fatal("cancelled observation succeeded")
	}
}

func TestReplacementPingUnitTerminalAndRecoveryObservation(t *testing.T) {
	program, _ := json.Marshal(replacementPingUnitStatusProgram)
	fixture := `import json,sys,types,os
from pathlib import Path
d=Path(sys.argv[2]);binding='a'*64
source=json.loads(sys.argv[1]).replace('/var/lib/ultra-exit-ping',str(d/'exit')).replace('/var/lib/ultra-replacement-ping',str(d/'publication'))
source=source.replace('s.st_uid==0','True') # Unprivileged fixture trust root only.
source=source.replace('for p in [d,*d.parents]:','for p in [d]:')
ns={'__name__':'fixture'};exec(source,ns);ns['os'].geteuid=lambda:0
for kind in ('exit','publication'):(d/kind/binding).mkdir(mode=0o700,parents=True)
receipt=d/'exit'/binding/'receipt.json';receipt.write_text(json.dumps({'binding':binding,'state':'succeeded'}));receipt.chmod(0o600)
unit=['active','success']
def run(args,**kwargs):
 assert kwargs['timeout']==5
 return types.SimpleNamespace(returncode=0,stdout='LoadState=loaded\nActiveState='+unit[0]+'\nResult='+unit[1]+'\n')
ns['subprocess'].run=run
assert ns['observe']('exit','update',binding,1)['state']=='running' # Receipt alone cannot prove stopped worker.
unit[0]='deactivating';assert ns['observe']('exit','update',binding,1)['state']=='running'
unit[0]='inactive';assert ns['observe']('exit','update',binding,1)['verified']
unit[1]='exit-code';receipt.write_text(json.dumps({'binding':binding,'state':'rolled_back'}))
assert ns['observe']('exit','update',binding,1)['state']=='failed'
assert ns['observe']('exit','rollback',binding,1)['verified']
assert ns['observe']('exit','stop-update',binding,1)['verified']
receipt.write_text(json.dumps({'binding':'b'*64,'state':'rolled_back'}))
assert ns['observe']('exit','rollback',binding,1)['state']=='failed'
publication=d/'publication'/binding/'publication-publish-receipt.json';publication.write_text(json.dumps({'binding':binding,'state':'applying'}));publication.chmod(0o600)
assert ns['observe']('publication','publish',binding,2)['state']=='failed'
publication.write_text(json.dumps({'binding':binding,'state':'rolled_back'}))
assert ns['observe']('publication','disable',binding,2)['verified']
ns['stop_worker']('exit','update',binding);assert (d/'exit'/binding/'cancelled').read_text()=='cancelled'
ns['stop_worker']('publication','publish',binding);assert (d/'publication'/binding/'cancelled-publish').read_text()=='cancelled'
`
	command := exec.Command("python3", "-c", fixture, string(program), t.TempDir())
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("unit state fixture %v: %s", err, out)
	}
	for _, tc := range []struct {
		source        string
		runtime, stop string
	}{{replacementPingExitDispatch, "RuntimeMaxSec=150", "TimeoutStopSec=120"}, {replacementPingBridgeProgram, "RuntimeMaxSec=240", "TimeoutStopSec=240"}} {
		if !strings.Contains(tc.source, tc.runtime) || !strings.Contains(tc.source, tc.stop) || strings.Contains(tc.source, "'--wait'") {
			t.Fatal("worker dispatch must use independent bounded execution and recovery, not an SSH-length wait")
		}
	}
}
