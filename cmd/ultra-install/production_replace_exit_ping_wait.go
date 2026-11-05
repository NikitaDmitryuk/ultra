package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

// Workers outlive individual SSH sessions. Runtime and independent stop/recovery
// budgets are observed through bounded read-only polls, never a replayed submit.
const replacementPingPublicationWait = 510 * time.Second     // 240 run + 240 recovery + 30 transport margin.
const replacementPingExitWait = 330 * time.Second            // 150 run + 120 recovery + 60 upload/transport margin.
const replacementPingPublicationStopWait = 270 * time.Second // 240 recovery + 30 transport margin.
const replacementPingExitStopWait = 150 * time.Second        // 120 recovery + 30 transport margin.

type replacementPingOperationState struct {
	Binding  string `json:"binding"`
	State    string `json:"state"`
	Verified bool   `json:"verified"`
	Count    int    `json:"count"`
}

func waitReplacementPingOperation(
	ctx context.Context,
	binding string,
	observe func(context.Context) ([]byte, error),
	pause func(context.Context) error,
) ([]byte, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, errors.New("replacement_exit_ping_observation_timeout")
		}
		raw, err := observe(ctx)
		if err != nil {
			return nil, fmt.Errorf("replacement_exit_ping_observation_uncertain: %w", err)
		}
		var state replacementPingOperationState
		if json.Unmarshal(raw, &state) != nil || state.Binding != binding {
			return nil, errors.New("replacement_exit_ping_observation_invalid")
		}
		switch state.State {
		case "succeeded":
			if !state.Verified {
				return nil, errors.New("replacement_exit_ping_terminal_unverified")
			}
			return raw, nil
		case "running":
			if err = pause(ctx); err != nil {
				return nil, errors.New("replacement_exit_ping_observation_timeout")
			}
		default:
			return nil, errors.New("replacement_exit_ping_worker_failed")
		}
	}
}

func runReplacementPingOperation(
	ctx context.Context,
	p *installplan.InstallPlan,
	rollout *replacementPingRollout,
	program, mode string,
	index int,
) ([]byte, error) {
	budget := replacementPingPublicationWait
	if mode == "update" || mode == "rollback" {
		budget = replacementPingExitWait
	}
	if mode == "rollback" {
		budget += replacementPingExitStopWait
	}
	if mode == "disable" {
		budget += replacementPingPublicationStopWait
	}
	operation, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if mode == "disable" || mode == "rollback" {
		stopMode := "stop-publish"
		if mode == "rollback" {
			stopMode = "stop-update"
		}
		if _, err := retainedMutation(operation, p, p.Bridge.SSHHost, p.BridgeSSHIdentity(), false, program, []string{string(mustReplacementJSON(rollout)), stopMode, fmt.Sprint(index)}); err != nil {
			return nil, err
		}
		if _, err := waitReplacementPingOperation(operation, rollout.Binding, func(ctx context.Context) ([]byte, error) {
			return retainedRemote(ctx, p, p.Bridge.SSHHost, p.BridgeSSHIdentity(), false, program, []string{string(mustReplacementJSON(rollout)), "status-" + stopMode, fmt.Sprint(index)})
		}, replacementPingPollPause); err != nil {
			return nil, err
		}
	}
	raw, err := retainedMutation(
		operation,
		p,
		p.Bridge.SSHHost,
		p.BridgeSSHIdentity(),
		false,
		program,
		[]string{string(mustReplacementJSON(rollout)), mode, fmt.Sprint(index)},
	)
	if err != nil {
		return nil, err
	}
	var state replacementPingOperationState
	if json.Unmarshal(raw, &state) != nil || state.Binding != rollout.Binding {
		return nil, errors.New("replacement_exit_ping_submission_invalid")
	}
	if state.Verified {
		return raw, nil
	} // No publication backup exists: already safely disabled.
	if state.State != "running" {
		return nil, errors.New("replacement_exit_ping_submission_unverified")
	}
	return waitReplacementPingOperation(operation, rollout.Binding, func(ctx context.Context) ([]byte, error) {
		return retainedRemote(
			ctx,
			p,
			p.Bridge.SSHHost,
			p.BridgeSSHIdentity(),
			false,
			program,
			[]string{string(mustReplacementJSON(rollout)), "status-" + mode, fmt.Sprint(index)},
		)
	}, replacementPingPollPause)
}

func replacementPingPollPause(ctx context.Context) error {
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

const replacementPingUnitStatusProgram = `import os,sys,json,subprocess,stat
from pathlib import Path
def need(v,c):
 if not v:raise ValueError(c)
def stop_worker(kind,target,binding):
 need(os.geteuid()==0 and len(binding)==64 and all(c in '0123456789abcdef' for c in binding),'exit_ping_stop_invalid')
 need((kind,target) in (('exit','update'),('publication','publish')),'exit_ping_stop_invalid')
 base=Path('/var/lib/ultra-exit-ping' if kind=='exit' else '/var/lib/ultra-replacement-ping');d=base/binding
 for p in [d,*d.parents]:
  if p.exists():
   s=p.lstat();need(not stat.S_ISLNK(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,'exit_ping_stop_path_untrusted')
 base.mkdir(mode=0o700,exist_ok=True);d.mkdir(mode=0o700,exist_ok=True)
 marker=d/('cancelled' if kind=='exit' else 'cancelled-publish')
 try:
  fd=os.open(marker,os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,0o600);os.write(fd,b'cancelled');os.fsync(fd);os.close(fd)
 except FileExistsError:need(marker.is_file() and not marker.is_symlink(),'exit_ping_stop_marker_untrusted')
 fd=os.open(d,os.O_DIRECTORY);os.fsync(fd);os.close(fd)
 unit=('ultra-exit-ping-' if kind=='exit' else 'ultra-ping-publication-publish-')+binding+'.service'
 subprocess.run(['systemctl','stop','--no-block',unit],capture_output=True,timeout=5)
def observe(kind,mode,binding,count):
 need(os.geteuid()==0 and len(binding)==64 and all(c in '0123456789abcdef' for c in binding),'exit_ping_status_invalid')
 stopping=mode.startswith('stop-');target=mode[5:] if stopping else mode
 if kind=='exit':
  need(target in ('update','rollback'),'exit_ping_status_invalid');d=Path('/var/lib/ultra-exit-ping')/binding
  unit=('ultra-exit-ping-' if target=='update' else 'ultra-exit-ping-rollback-')+binding;receipt=d/'receipt.json';expected='rolled_back' if target=='rollback' else 'succeeded'
 else:
  need(kind=='publication' and target in ('stage','publish','disable'),'exit_ping_status_invalid');d=Path('/var/lib/ultra-replacement-ping')/binding
  unit=('ultra-ping-disable-' if target=='disable' else 'ultra-ping-publication-'+target+'-')+binding
  receipt=d/('publication-'+('publish' if target=='disable' else target)+'-receipt.json');expected='rolled_back' if target=='disable' else 'succeeded'
 q=subprocess.run(['systemctl','show','--property=LoadState','--property=ActiveState','--property=Result',unit+'.service'],capture_output=True,text=True,timeout=5)
 values=dict(line.split('=',1) for line in q.stdout.splitlines() if '=' in line)
 need(values.get('LoadState') in ('loaded','not-found'),'exit_ping_unit_state_unavailable')
 active=values.get('ActiveState')
 if active in ('active','activating','deactivating','reloading'):return {'binding':binding,'state':'running'}
 need(active in ('inactive','failed') or values['LoadState']=='not-found','exit_ping_unit_state_unavailable')
 if stopping:return {'binding':binding,'state':'succeeded','verified':True,'count':count}
 state={}
 if receipt.exists():
  s=receipt.lstat();need(stat.S_ISREG(s.st_mode) and not s.st_mode&0o077 and s.st_uid==0,'exit_ping_receipt_untrusted');state=json.loads(receipt.read_text())
 success=state.get('binding')==binding and state.get('state')==expected
 # A failed ExecStart may have recovered correctly, but never proves update success.
 if target in ('stage','publish','update'):success=success and (values['LoadState']=='not-found' or values.get('Result')=='success')
 return {'binding':binding,'state':'succeeded' if success else 'failed','verified':success,'count':count}
if __name__=='__main__':print(json.dumps(observe(sys.argv[1],sys.argv[2],sys.argv[3],int(sys.argv[4]))))
`
