package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/NikitaDmitryuk/ultra/internal/adminapi"
	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/cloudinstall"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
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

func configureCloud(
	ctx context.Context,
	wg *sync.WaitGroup,
	srv *adminapi.Server,
	database *db.DB,
	spec *config.Spec,
	exitMgr *exits.Manager,
	apply, refresh func(context.Context) error,
	log *slog.Logger,
) {
	socket := os.Getenv("ULTRA_ANSIBLE_SOCKET")
	if socket == "" {
		socket = "/run/ultra-ansible/controller.sock"
	}
	controller := deployansible.Client{Socket: socket}
	srv.TopologyReady = controller.Ready
	srv.TopologyFrozen = controller.TopologyFrozen
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
	p := &cloudinstall.Provisioner{
		DB:       database,
		Bridge:   spec,
		Exits:    exitMgr,
		Routes:   routes,
		Identity: identity,
		BridgeIP: bridgeIP,
		StateDir: stateDir,
		Binary:   binary,
		Apply:    apply,
		Refresh:  refresh,
	}
	p.Configurer = controller
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
	srv.Cloud = &cloud.Service{
		TopologyReady:     controller.Ready,
		IngressInstanceID: os.Getenv("ULTRA_SUBSCRIPTION_INGRESS_INSTANCE_ID"),
		API:               api,
		Store:             store,
		Provisioner:       p,
		Log:               log,
	}
	wg.Add(1)
	go func() { defer wg.Done(); srv.Cloud.Run(ctx) }()
}
