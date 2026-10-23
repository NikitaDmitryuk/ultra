package main

import (
	"encoding/json"
	"errors"
)

type providerRetirementRequest struct {
	Protocol       string                  `json:"protocol"`
	Binding        string                  `json:"binding_sha256"`
	Restore        string                  `json:"restore_sha256"`
	DeletionSHA256 string                  `json:"deletion_sha256"`
	Primary        retainedPrimaryIdentity `json:"primary"`
	Fleet          []bridgeReimageFleetRow `json:"fleet"`
	OperationID    string                  `json:"operation_id"`
	ExitID         string                  `json:"exit_id"`
	InstanceID     string                  `json:"instance_id"`
	Address        string                  `json:"address"`
}

func providerRetirementPlan(
	in retainedPrimaryRebuildInput,
	evidence retainedReconcileEvidence,
	deletionRaw, fleetRaw []byte,
) (providerRetirementRequest, error) {
	var result providerRetirementRequest
	var deletion providerDeleteReceipt
	if !in.BridgeOnly || in.RetainedExit == nil || decodeRetainedReconcile(deletionRaw, &deletion) != nil ||
		deletion.Intent.Protocol != "ultra-provider-delete-intent-v1" || deletion.Result != "provider-instance-absent" || deletion.ObservedAt <= 0 ||
		!runtimeHostValidDigest(deletion.Intent.ConfigSHA256) || !runtimeHostValidDigest(deletion.Intent.CensusSHA256) {
		return result, errors.New("provider_retirement_deletion_proof_invalid")
	}
	fleet, err := normalizeBridgeReimageFleet(fleetRaw)
	if err != nil {
		return result, err
	}
	if _, _, err = validateBridgeReimageFleet(fleet, in); err != nil {
		return result, err
	}
	exits := map[string]bridgeReimageFleetRow{}
	for _, row := range fleet {
		if row.Kind == "exit" {
			exits[row.ID] = row
		}
	}
	found := 0
	for _, row := range fleet {
		if row.Kind != "cloud_operation" || row.InstanceID != deletion.Intent.InstanceID {
			continue
		}
		exit := exits[row.ExitID]
		if row.State != "ready" || !row.OccupiesSlot || !exit.Enabled || exit.Address != deletion.Intent.Address {
			return result, errors.New("provider_retirement_target_changed")
		}
		result.OperationID = row.ID
		result.ExitID = row.ExitID
		found++
	}
	if found != 1 {
		return result, errors.New("provider_retirement_exact_ready_target_required")
	}
	evidenceRaw, _ := json.Marshal(evidence)
	result.Protocol = "ultra-provider-absence-retirement-v1"
	result.Restore = digestSHA256(evidenceRaw)
	result.DeletionSHA256 = digestSHA256(deletionRaw)
	result.Primary = in.Primary
	result.Fleet = fleet
	result.InstanceID = deletion.Intent.InstanceID
	result.Address = deletion.Intent.Address
	raw, _ := json.Marshal(result)
	result.Binding = digestSHA256(raw)
	return result, nil
}

const providerRetirementRemote = `import sys,subprocess,json,base64
request=json.loads(base64.b64decode(sys.argv[2],validate=True))
query="""
BEGIN;
SET LOCAL lock_timeout='5s';
SET LOCAL statement_timeout='20s';
CREATE TEMP TABLE retirement_input(value jsonb) ON COMMIT DROP;
INSERT INTO retirement_input VALUES (:'request'::jsonb);
DO $guard$
BEGIN
 IF NOT pg_try_advisory_xact_lock(817365005) OR NOT pg_try_advisory_xact_lock(817365006)
 OR NOT pg_try_advisory_xact_lock(817365007) OR NOT pg_try_advisory_xact_lock(817365010)
 OR NOT pg_try_advisory_xact_lock(817365011) THEN RAISE EXCEPTION 'retirement_busy'; END IF;
END $guard$;
LOCK TABLE public.exit_nodes,public.cloud_operations,public.vpn_locations IN SHARE ROW EXCLUSIVE MODE;
LOCK TABLE public.schema_migrations IN SHARE MODE;
CREATE TEMP VIEW retirement_fleet AS
 SELECT 'exit'::text kind,id::text,address,port,enabled,COALESCE(pinned_peer_cert_sha256,'') pinned_peer_cert_sha256,
 ''::text retirement_binding,''::text state,''::text phase,''::text instance_id,''::text exit_id,false occupies_slot,''::text install_attempt FROM public.exit_nodes
 UNION ALL
 SELECT 'cloud_operation',id::text,'',0,false,'',COALESCE(body#>>'{provider_absence_retirement,binding_sha256}',''),state,COALESCE(body->>'phase',''),COALESCE(body->>'instance_id',''),
 COALESCE(body->>'exit_id',''),occupies_slot,COALESCE(body->>'install_attempt','') FROM public.cloud_operations;
CREATE TEMP TABLE retirement_expected ON COMMIT DROP AS SELECT r.* FROM retirement_input,
 jsonb_to_recordset(value->'fleet') AS r(kind text,id text,address text,port integer,enabled boolean,pinned_peer_cert_sha256 text,retirement_binding text,
 state text,phase text,instance_id text,exit_id text,occupies_slot boolean,install_attempt text);
DO $retire$
DECLARE req jsonb; op public.cloud_operations%ROWTYPE; receipt jsonb; n integer; routes integer; saved jsonb;
BEGIN
 SELECT value INTO STRICT req FROM retirement_input;
 IF pg_is_in_recovery() OR (SELECT system_identifier::text FROM pg_control_system())<>req#>>'{primary,system_identifier}'
 OR current_database()<>req#>>'{primary,database}'
 OR (SELECT oid::text FROM pg_database WHERE datname=current_database())<>req#>>'{primary,database_oid}'
 OR (SELECT COALESCE(string_agg(version::text,',' ORDER BY version),'') FROM public.schema_migrations)<>req#>>'{primary,migration_versions}'
 THEN RAISE EXCEPTION 'retirement_primary_changed'; END IF;
 IF EXISTS(SELECT 1 FROM public.cloud_operations WHERE state IN ('pending','unknown') OR (body->>'state') IS DISTINCT FROM state)
 THEN RAISE EXCEPTION 'retirement_queue_changed'; END IF;
 SELECT * INTO STRICT op FROM public.cloud_operations WHERE id::text=req->>'operation_id' FOR UPDATE;
 saved:=op.body->'provider_absence_retirement';
 IF saved IS NOT NULL THEN
  IF saved->>'binding_sha256' IS DISTINCT FROM req->>'binding_sha256' OR saved->>'protocol' IS DISTINCT FROM req->>'protocol'
  OR op.state<>'deleted' OR op.occupies_slot OR op.body->>'state'<>'deleted' OR op.body->>'phase'<>'cleanup'
  OR op.body->>'instance_id' IS DISTINCT FROM req->>'instance_id' OR op.body->>'exit_id' IS DISTINCT FROM req->>'exit_id'
  OR EXISTS(SELECT 1 FROM public.vpn_locations WHERE exit_id::text=req->>'exit_id')
  OR (SELECT count(*) FROM public.cloud_operation_events WHERE operation_id=op.id AND phase='provider_absence_retirement'
      AND outcome='succeeded' AND code=req->>'binding_sha256')<>1
  THEN RAISE EXCEPTION 'retirement_resume_changed'; END IF;
  UPDATE retirement_expected SET enabled=false WHERE kind='exit' AND id=req->>'exit_id';
  UPDATE retirement_expected SET state='deleted',phase='cleanup',occupies_slot=false,retirement_binding=req->>'binding_sha256' WHERE kind='cloud_operation' AND id=req->>'operation_id';
 END IF;
 IF EXISTS((SELECT * FROM retirement_fleet EXCEPT SELECT * FROM retirement_expected)
 UNION ALL (SELECT * FROM retirement_expected EXCEPT SELECT * FROM retirement_fleet))
 THEN RAISE EXCEPTION 'retirement_fleet_changed'; END IF;
 IF saved IS NOT NULL THEN RETURN; END IF;
 IF op.state<>'ready' OR NOT op.occupies_slot OR op.body->>'state'<>'ready'
 OR op.body->>'instance_id' IS DISTINCT FROM req->>'instance_id' OR op.body->>'exit_id' IS DISTINCT FROM req->>'exit_id'
 OR NOT EXISTS(SELECT 1 FROM public.exit_nodes WHERE id::text=req->>'exit_id' AND address=req->>'address' AND enabled)
 OR NOT EXISTS(SELECT 1 FROM public.exit_nodes WHERE id::text<>req->>'exit_id' AND enabled)
 OR EXISTS(SELECT 1 FROM public.cloud_operations WHERE id<>op.id AND occupies_slot AND body->'offer'->>'replace_id'=req->>'exit_id')
 THEN RAISE EXCEPTION 'retirement_target_changed'; END IF;
 SELECT count(*) INTO routes FROM public.vpn_locations WHERE exit_id::text=req->>'exit_id';
 UPDATE public.exit_nodes SET enabled=false WHERE id::text=req->>'exit_id' AND enabled;
 GET DIAGNOSTICS n=ROW_COUNT; IF n<>1 THEN RAISE EXCEPTION 'retirement_exit_count'; END IF;
 UPDATE public.vpn_locations SET published=false,exit_id=NULL WHERE exit_id::text=req->>'exit_id';
 GET DIAGNOSTICS n=ROW_COUNT; IF n<>routes THEN RAISE EXCEPTION 'retirement_route_count'; END IF;
 receipt:=jsonb_build_object('protocol',req->>'protocol','binding_sha256',req->>'binding_sha256',
 'deletion_sha256',req->>'deletion_sha256','operation_id',req->>'operation_id','exit_id',req->>'exit_id',
 'instance_id',req->>'instance_id','exit_rows',1,'operation_rows',1,'route_rows',routes,'event_rows',1);
 UPDATE public.cloud_operations SET state='deleted',occupies_slot=false,
 body=body||jsonb_build_object('state','deleted','phase','cleanup','charged',false,'provider_absence_retirement',receipt)
 WHERE id=op.id AND state='ready' AND occupies_slot;
 GET DIAGNOSTICS n=ROW_COUNT; IF n<>1 THEN RAISE EXCEPTION 'retirement_operation_count'; END IF;
 INSERT INTO public.cloud_operation_events(operation_id,phase,outcome,code)
 VALUES(op.id,'provider_absence_retirement','succeeded',req->>'binding_sha256');
 GET DIAGNOSTICS n=ROW_COUNT; IF n<>1 THEN RAISE EXCEPTION 'retirement_event_count'; END IF;
END $retire$;
SELECT body->'provider_absence_retirement' FROM public.cloud_operations WHERE id::text=(SELECT value->>'operation_id' FROM retirement_input);
COMMIT;
"""
r=subprocess.run(['runuser','-u','postgres','--','psql','--no-psqlrc','-qAt','-v','ON_ERROR_STOP=1','-v','request='+json.dumps(request),'-d',sys.argv[1]],input=query,capture_output=True,text=True,timeout=30)
if r.returncode:raise ValueError('provider_retirement_transaction_failed')
value=json.loads(r.stdout);assert value['binding_sha256']==request['binding_sha256']
print(json.dumps(value,separators=(',',':'),sort_keys=True))
`
