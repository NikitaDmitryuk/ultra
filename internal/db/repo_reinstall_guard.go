package db

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/google/uuid"
)

var ErrExitTargetBusy = errors.New("exit target is reserved for cloud maintenance")

// The namespace prefix keeps address locks separate from fixed topology locks.
// All ports on a host share one relay spec and service, so the lock owns the IP.
func exitTargetLock(address string) int64 {
	address = strings.ToLower(strings.TrimSpace(address))
	if ip := net.ParseIP(address); ip != nil {
		address = ip.String()
	}
	sum := sha256.Sum256([]byte("ultra-exit-target-v1:" + address))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

// Mutation callers hold the short topology mutex first. A shared transaction
// lock allows unrelated mutations while excluding a host-wide remote reinstall.
func (r *ExitNodeRepo) targetMutable(ctx context.Context, id string, addresses ...string) error {
	if r.transaction == nil {
		return errors.New("exit topology transaction required")
	}
	// Completed ordinary deletion releases the physical address, but its exact
	// operation/exit identity must never be reused, even at another address.
	if id != "" {
		parsed, err := uuid.Parse(id)
		if err != nil {
			return err
		}
		id = parsed.String()
	}
	var tombstone bool
	if err := r.transaction.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cloud_operations c
WHERE c.state='deleted' AND c.body->>'phase' IN ('delete','cleanup')
AND $1<>'' AND (c.id::text=$1 OR c.body->>'exit_id'=$1))`, id).Scan(&tombstone); err != nil {
		return err
	}
	if tombstone {
		return ErrExitTargetBusy
	}
	rows, err := r.transaction.Query(
		ctx,
		`SELECT body->>'reinstall_target' FROM cloud_operations WHERE COALESCE(body->>'reinstall_target','')<>''
UNION ALL
SELECT n.address FROM exit_nodes n JOIN cloud_operations c
ON n.id::text=COALESCE(NULLIF(c.body->>'exit_id',''), c.id::text)
WHERE c.body->>'phase' IN ('retire_unpublish','retire_delete','retire_cleanup','delete','cleanup')
AND NOT (c.state='deleted' AND c.body->>'phase' IN ('delete','cleanup'))
AND NOT (n.id::text=$1 AND c.body->>'phase'='retire_unpublish' AND c.state='pending')
UNION ALL
SELECT c.body->>'retirement_target' FROM cloud_operations c
WHERE c.body->>'phase' IN ('retire_unpublish','retire_delete','retire_cleanup','delete','cleanup')
AND NOT (c.state='deleted' AND c.body->>'phase' IN ('delete','cleanup'))
AND COALESCE(c.body->>'retirement_target','')<>''
AND NOT (c.id::text=$1 AND c.body->>'phase'='retire_unpublish' AND c.state='pending')`,
		r.retirementDisableID,
	)
	if err != nil {
		return err
	}
	var reserved []string
	for rows.Next() {
		var address string
		if err := rows.Scan(&address); err != nil {
			rows.Close()
			return err
		}
		reserved = append(reserved, address)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, address := range addresses {
		for _, target := range reserved {
			if exitTargetLock(address) == exitTargetLock(target) {
				return ErrExitTargetBusy
			}
		}
		var available bool
		if err := r.transaction.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock_shared($1)`, exitTargetLock(address)).Scan(&available); err != nil {
			return err
		}
		if !available {
			return ErrExitTargetBusy
		}
	}
	return nil
}

// ValidateCloudRetirementTarget checks every row on the physical host, including
// disabled rows and different ports. The caller holds the topology mutex before
// the cloud worker lock, so the check and persisted reservation cannot race CRUD.
func (r *ExitNodeRepo) ValidateCloudRetirementTarget(ctx context.Context, op *cloud.Operation) error {
	return r.validateCloudDeletionTarget(ctx, op, false)
}

// ValidateCloudDeleteTarget permits ordinary deletion beside disabled historical
// exits only when a completed ordinary deletion proves a distinct VPS identity.
// Explicit retirement intentionally retains its stricter alias policy.
func (r *ExitNodeRepo) ValidateCloudDeleteTarget(ctx context.Context, op *cloud.Operation) error {
	if op == nil || (op.Phase != "unpublish" && op.Phase != "delete" && op.Phase != "cleanup") {
		return cloud.ErrConflict
	}
	return r.validateCloudDeletionTarget(ctx, op, true)
}

func (r *ExitNodeRepo) validateCloudDeletionTarget(ctx context.Context, op *cloud.Operation, ordinary bool) error {
	if op == nil || op.ID == "" || (op.ExitID != "" && op.ExitID != op.ID) {
		return cloud.ErrConflict
	}
	ip := net.ParseIP(op.RetirementTarget)
	if ip == nil || ip.To4() == nil {
		return cloud.ErrConflict
	}
	nodes, err := r.List(ctx)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		nodeIP := net.ParseIP(node.Address)
		sameHost := nodeIP != nil && ip.Equal(nodeIP)
		if node.ID == op.ExitID {
			if !sameHost ||
				((op.Phase == "retire_delete" || op.Phase == "retire_cleanup" || op.Phase == "delete" || op.Phase == "cleanup") && node.Enabled) {
				return cloud.ErrConflict
			}
		} else if sameHost || node.ID == op.ID {
			if ordinary && sameHost && !node.Enabled && node.ID != op.ID && op.InstanceID != "" {
				var historical bool
				if err := r.db.Pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cloud_operations c
WHERE c.state='deleted' AND c.body->>'phase' IN ('delete','cleanup')
AND c.id::text=$1 AND COALESCE(NULLIF(c.body->>'exit_id',''), c.id::text)=$1
AND c.id::text<>$2 AND COALESCE(c.body->>'instance_id','')<>'' AND c.body->>'instance_id'<>$3
AND COALESCE(c.body->>'reinstall_target','')=''
AND (COALESCE(c.body->>'retirement_target','')='' OR c.body->>'retirement_target'=$4))`, node.ID, op.ID, op.InstanceID, ip.String()).Scan(&historical); err != nil {
					return err
				}
				if historical {
					continue
				}
			}
			return cloud.ErrConflict
		}
	}
	return nil
}

// ReserveCloudReinstall binds the worker job to an already committed host
// reservation. The guarded CAS cannot resurrect a cleared or changed target.
func (r *ExitNodeRepo) ReserveCloudReinstall(ctx context.Context, op *cloud.Operation, jobID string, target string) error {
	if _, err := toPGUUID(jobID); err != nil || jobID == "" || net.ParseIP(target) == nil || !op.Reinstall {
		return cloud.ErrConflict
	}
	target = net.ParseIP(target).String()
	if op.ReinstallTarget != target || (op.ReinstallJobID != "" && op.ReinstallJobID != jobID) {
		return cloud.ErrConflict
	}
	before, err := json.Marshal(op)
	if err != nil {
		return err
	}
	reserved := *op
	reserved.ReinstallJobID, reserved.ReinstallTarget = jobID, target
	after, err := json.Marshal(reserved)
	if err != nil {
		return err
	}
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365010)`); err != nil {
		return err
	}
	result, err := tx.Exec(
		ctx,
		`UPDATE cloud_operations SET body=$3::jsonb WHERE id=$1 AND state='pending' AND body=$2::jsonb`,
		op.ID,
		before,
		after,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return cloud.ErrConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	*op = reserved
	return nil
}

// ClearCloudReinstall releases a preflight reservation with no bound job, or is
// called after the controller proves a bound receipt terminal. Its CAS prevents
// clearing a job that concurrently bound after the caller read an unbound target.
func (r *ExitNodeRepo) ClearCloudReinstall(ctx context.Context, op *cloud.Operation) error {
	if op.ReinstallTarget == "" {
		return cloud.ErrConflict
	}
	tx, err := r.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365010)`); err != nil {
		return err
	}
	result, err := tx.Exec(ctx, `UPDATE cloud_operations SET body=body-'reinstall_job_id'-'reinstall_target'
WHERE id=$1 AND COALESCE(body->>'reinstall_job_id','')=$2 AND body->>'reinstall_target'=$3 AND body->>'instance_id'=$4 AND body->>'exit_id'=$5`, op.ID, op.ReinstallJobID, op.ReinstallTarget, op.InstanceID, op.ExitID)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return cloud.ErrConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	op.ReinstallJobID, op.ReinstallTarget = "", ""
	return nil
}

// GuardCloudReinstall validates and commits durable host ownership atomically
// under the topology mutex before SSH preflight. The optional session lock is
// only additional exclusion: losing that session cannot release the target.
func (r *ExitNodeRepo) GuardCloudReinstall(
	ctx context.Context,
	op *cloud.Operation,
	target exits.Node,
	instance cloud.Instance,
) (func(), error) {
	if !op.Reinstall || op.State != "pending" || op.Phase != "install" || op.ID != target.ID || op.ExitID != target.ID ||
		op.InstanceID == "" || op.InstanceID != instance.ID || target.Enabled || net.ParseIP(target.Address) == nil || target.Address != instance.IP {
		return nil, cloud.ErrConflict
	}
	conn, err := r.db.Pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	held, retained := false, false
	key := exitTargetLock(target.Address)
	release := func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if held {
			var unlocked bool
			if err := conn.QueryRow(cleanup, `SELECT pg_advisory_unlock($1)`, key).Scan(&unlocked); err != nil || !unlocked {
				_ = conn.Conn().Close(cleanup)
			}
		}
		conn.Release()
	}
	defer func() {
		if !retained {
			release()
		}
	}()
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.Background()) //nolint:errcheck
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(817365010)`); err != nil {
		return nil, err
	}
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&held); err != nil {
		return nil, err
	}
	if !held {
		return nil, ErrExitTargetBusy
	}
	body, err := json.Marshal(op)
	if err != nil {
		return nil, err
	}
	var exact bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cloud_operations WHERE id=$1 AND state='pending' AND body=$2::jsonb)`, op.ID, body).Scan(&exact); err != nil {
		return nil, err
	}
	if !exact {
		return nil, cloud.ErrConflict
	}
	repo := &ExitNodeRepo{db: &DB{Pool: r.db.Pool, Queries: r.db.Queries.WithTx(tx)}, transaction: tx}
	current, err := repo.Get(ctx, target.ID)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(current, target) {
		return nil, cloud.ErrConflict
	}
	nodes, err := repo.List(ctx)
	if err != nil {
		return nil, err
	}
	targetIP := net.ParseIP(target.Address)
	for _, node := range nodes {
		if node.ID != target.ID && targetIP.Equal(net.ParseIP(strings.TrimSpace(node.Address))) {
			return nil, cloud.ErrConflict
		}
	}
	var alias bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cloud_operations WHERE id<>$1 AND body->>'instance_id'=$2)`, op.ID, op.InstanceID).Scan(&alias); err != nil {
		return nil, err
	}
	if alias {
		return nil, cloud.ErrConflict
	}
	reserved := *op
	if reserved.ReinstallTarget != "" && reserved.ReinstallTarget != targetIP.String() {
		return nil, cloud.ErrConflict
	}
	reserved.ReinstallTarget = targetIP.String()
	reservedBody, err := json.Marshal(reserved)
	if err != nil {
		return nil, err
	}
	result, err := tx.Exec(
		ctx,
		`UPDATE cloud_operations SET body=$3::jsonb WHERE id=$1 AND state='pending' AND body=$2::jsonb`,
		op.ID,
		body,
		reservedBody,
	)
	if err != nil {
		return nil, err
	}
	if result.RowsAffected() != 1 {
		return nil, cloud.ErrConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	*op = reserved
	retained = true
	var once sync.Once
	return func() { once.Do(release) }, nil
}

// DisableCloudRetirement is the sole mutation allowed by a retirement reservation.
// The transaction must still observe the exact pending unpublish identity; all
// external Update calls and terminal tombstones retain the ordinary guard.
func (r *ExitNodeRepo) DisableCloudRetirement(ctx context.Context, op *cloud.Operation) error {
	if op == nil || op.ID == "" || op.ExitID != op.ID || op.Phase != "retire_unpublish" || op.State != "pending" ||
		net.ParseIP(op.RetirementTarget) == nil {
		return cloud.ErrConflict
	}
	return r.withMutation(ctx, func(repo *ExitNodeRepo) error {
		var exact bool
		if err := repo.transaction.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM cloud_operations WHERE id::text=$1 AND state='pending' AND body->>'phase'='retire_unpublish' AND body->>'exit_id'=$1 AND body->>'instance_id'=$2 AND body->>'retirement_target'=$3)`, op.ID, op.InstanceID, op.RetirementTarget).Scan(&exact); err != nil {
			return err
		}
		if !exact {
			return cloud.ErrConflict
		}
		if err := repo.ValidateCloudRetirementTarget(ctx, op); err != nil {
			return err
		}
		repo.retirementDisableID = op.ID
		disabled := false
		_, err := repo.update(ctx, op.ExitID, exits.UpdatePatch{Enabled: &disabled})
		return err
	})
}
