-- name: LockCloudReservation :exec
SELECT pg_advisory_xact_lock(817365005);

-- name: CloudOperationBody :one
SELECT body FROM cloud_operations WHERE id=$1;

-- name: CloudReplacementEligible :one
-- Existing JSON can predate canonical persistence, including UUID URN spelling.
SELECT EXISTS(SELECT 1 FROM cloud_operations ready WHERE ready.id=$1 AND ready.state='ready')
 AND NOT EXISTS(SELECT 1 FROM cloud_operations replacement WHERE replacement.occupies_slot AND NULLIF(regexp_replace(replacement.body->'offer'->>'replace_id','^urn:uuid:','','i'),'')::uuid=$1);

-- name: CloudOccupiedSlots :one
SELECT COUNT(*) FROM cloud_operations WHERE occupies_slot;

-- name: CloudOfferValid :one
SELECT expires_at>NOW() AND actor=$2 FROM cloud_offers WHERE id=$1;

-- name: InsertReservedCloudOperation :exec
INSERT INTO cloud_operations(id,state,body) VALUES($1,$2,$3);

-- name: InsertCloudConfirmation :exec
INSERT INTO cloud_audit(actor,operation_id,action) VALUES($1,$2,'confirmed');

-- name: LockCloudWorker :exec
SELECT pg_advisory_lock(817365006);

-- name: UnlockCloudWorker :exec
SELECT pg_advisory_unlock(817365006);

-- name: LockCloudCapacity :exec
-- Keep separate from route/user/traffic locks (817365007).
SELECT pg_advisory_lock(817365011);

-- name: UnlockCloudCapacity :exec
SELECT pg_advisory_unlock(817365011);
