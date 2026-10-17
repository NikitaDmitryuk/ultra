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
)

var ErrExitTargetBusy = errors.New("exit target is being reinstalled")

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
func (r *ExitNodeRepo) targetMutable(ctx context.Context, addresses ...string) error {
	if r.transaction == nil {
		return errors.New("exit topology transaction required")
	}
	rows, err := r.transaction.Query(
		ctx,
		`SELECT body->>'reinstall_target' FROM cloud_operations WHERE COALESCE(body->>'reinstall_target','')<>''`,
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
