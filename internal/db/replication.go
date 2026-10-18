package db

import (
	"context"
	"time"
)

// BridgeReplicaStatus is the primary's live observation of the fixed physical
// standby. It is independent of exit-node provisioning and cached node records.
type BridgeReplicaStatus struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Source         string    `json:"source"`
	State          string    `json:"state"`
	ReplayLagBytes *int64    `json:"replay_lag_bytes"`
	CheckedAt      time.Time `json:"checked_at"`
}

func (d *DB) BridgeReplicationStatus(ctx context.Context) (any, error) {
	status := BridgeReplicaStatus{ID: "bridge", Name: "Bridge PostgreSQL standby", Source: "primary"}
	err := d.Pool.QueryRow(ctx,
		`SELECT state, replay_lag_bytes, checked_at FROM ultra_monitor.bridge_replication_status()`,
	).Scan(&status.State, &status.ReplayLagBytes, &status.CheckedAt)
	if err != nil {
		// Missing bootstrap function or failed query is an unavailable observation,
		// never evidence that the standby is disconnected or not configured.
		return nil, err
	}
	return []BridgeReplicaStatus{status}, nil
}
