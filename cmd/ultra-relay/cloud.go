package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/adminapi"
	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/cloudinstall"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/install"
	"github.com/NikitaDmitryuk/ultra/internal/replication"
)

func readCloudKey(path string) (string, error) {
	info, e := os.Stat(path)
	if e != nil || info.Mode().Perm()&0007 != 0 {
		return "", errors.New("cloud key unavailable")
	}
	value, e := os.ReadFile(path)
	if e != nil {
		return "", errors.New("cloud key unavailable")
	}
	key := strings.TrimSpace(string(value))
	if key == "" || strings.ContainsAny(key, "\r\n\t ") {
		return "", errors.New("cloud key invalid")
	}
	return key, nil
}
func configureCloud(ctx context.Context, wg *sync.WaitGroup, srv *adminapi.Server, database *db.DB, spec *config.Spec, exitMgr *exits.Manager, apply, refresh func(context.Context) error, log *slog.Logger) {
	identity := os.Getenv("ULTRA_VULTR_SSH_KEY_FILE")
	bridgeIP := os.Getenv("ULTRA_VULTR_BRIDGE_IP")
	stateDir := os.Getenv("ULTRA_VULTR_STATE_DIR")
	if stateDir == "" {
		stateDir = "/var/lib/ultra-relay/vultr"
	}
	routes := db.NewRouteRepo(database)
	store := db.NewCloudRepo(database)
	binary, e := os.Executable()
	if e != nil {
		return
	}
	p := &cloudinstall.Provisioner{DB: database, Bridge: spec, Exits: exitMgr, Routes: routes, Identity: identity, BridgeIP: bridgeIP, StateDir: stateDir, Binary: binary, Apply: apply, Refresh: refresh}
	replicaConfig, e := replication.Load(os.Getenv("ULTRA_REPLICATION_KEY_FILE"))
	if e == nil {
		replicas := replication.New(ctx, replicaConfig)
		replicas.Record = routes.ReplicationState
		p.Replica = replicas.Ensure
		p.CheckReady = replicas.Ready
		p.RemoveReplica = replicas.RemoveSlot
		srv.ReplicationStatus = routes.ReplicationStatuses
		wg.Add(1)
		go func() {
			defer wg.Done()
			runReplicaMonitor(ctx, database, exitMgr, store, replicas, identity, stateDir, log)
		}()
	} else {
		log.Warn("Vultr provisioning requires replication configuration")
	}
	var quotaAPI *cloud.Vultr
	defer func() { wg.Add(1); go func() { defer wg.Done(); runQuotas(ctx, database, quotaAPI, apply, log) }() }()
	path := os.Getenv("ULTRA_VULTR_KEY_FILE")
	if path == "" {
		return
	}
	key, e := readCloudKey(path)
	if e != nil {
		log.Warn("Vultr automation unavailable: API key not configured")
		return
	}
	api := cloud.NewVultr(key)
	quotaAPI = api
	p.API = api
	srv.Cloud = &cloud.Service{API: api, Store: store, Provisioner: p, Log: log}
	wg.Add(1)
	go func() { defer wg.Done(); srv.Cloud.Run(ctx) }()
}
func runReplicaMonitor(ctx context.Context, database *db.DB, exitMgr *exits.Manager, store *db.CloudRepo, manager *replication.Manager, identity, stateDir string, log *slog.Logger) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ops, e := store.List(ctx)
			if e != nil {
				continue
			}
			cloudNodes := map[string]string{}
			for _, op := range ops {
				cloudNodes[op.ID] = op.State
			}
			for _, node := range exitMgr.List() {
				if net.ParseIP(node.Address) == nil {
					continue
				}
				if state, managed := cloudNodes[node.ID]; managed && state != "ready" {
					continue
				}
				dir := filepath.Join(stateDir, node.ID)
				if os.MkdirAll(dir, 0700) != nil {
					continue
				}
				remote := install.Remote{Host: node.Address, Identity: identity, KnownHosts: filepath.Join(dir, "known_hosts")}
				var state string
				e = database.Pool.QueryRow(ctx, `SELECT state FROM node_replication WHERE node_id=$1`, node.ID).Scan(&state)
				if e != nil || state == "not_configured" || state == "insufficient_space" {
					c, cancel := context.WithTimeout(ctx, 10*time.Minute)
					_, err := manager.Ensure(c, node.ID, remote)
					cancel()
					if err != nil {
						_ = db.NewRouteRepo(database).ReplicationState(ctx, node.ID, "error", 0, 0, "bootstrap_failed")
						log.Warn("replica setup requires attention", "node", node.ID)
					}
				} else if state != "unexpected_primary" && state != "incompatible" {
					c, cancel := context.WithTimeout(ctx, 10*time.Second)
					_ = manager.Check(c, node.ID, remote)
					cancel()
				}
			}
		}
	}
}
