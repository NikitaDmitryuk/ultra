// Command ultra-relay runs the routing core in-process and serves one spec-defined role (bridge or exit).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/adminapi"
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/loglevel"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"github.com/NikitaDmitryuk/ultra/internal/stats"

	_ "github.com/xtls/xray-core/main/distro/all"
)

func main() {
	specPath := flag.String("spec", "", "path to relay JSON spec (required)")
	adminToken := flag.String(
		"admin-token",
		os.Getenv("ULTRA_RELAY_ADMIN_TOKEN"),
		"Bearer token for Admin API on bridge (loopback only). If empty, Admin API is disabled",
	)
	defLog := strings.TrimSpace(os.Getenv("ULTRA_RELAY_LOG_LEVEL"))
	if defLog == "" {
		defLog = "info"
	}
	logLevelFlag := flag.String(
		"log-level",
		defLog,
		"slog level and embedded xray loglevel: debug, info, warning|warn, error, none; also ULTRA_RELAY_LOG_LEVEL",
	)
	flag.Parse()

	slogLvl, xrayLogLevel, err := loglevel.ParseRelayLogLevel(*logLevelFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ultra-relay:", err)
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slogLvl}))
	log.Info("ultra-relay starting", "log_level", *logLevelFlag, "xray_loglevel", xrayLogLevel)

	if *specPath == "" {
		log.Error("missing -spec")
		os.Exit(2)
	}
	spec, err := config.LoadSpec(*specPath)
	if err != nil {
		log.Error("load spec", "err", err)
		os.Exit(1)
	}

	strat, err := mimic.New(spec.MimicPreset)
	if err != nil {
		log.Error("mimic preset", "err", err)
		os.Exit(1)
	}

	runner := new(proxy.Runner)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var wg sync.WaitGroup

	switch spec.Role {
	case config.RoleBridge:
		if spec.SplitRoutingEnabled() {
			if err := os.Setenv("XRAY_LOCATION_ASSET", spec.GeoAssetsDir); err != nil {
				log.Error("set XRAY_LOCATION_ASSET", "err", err)
				os.Exit(1)
			}
			rm := spec.RoutingMode
			if rm == "" {
				rm = config.RoutingModeBlocklist
			}
			log.Info("split routing enabled", "geo_assets_dir", spec.GeoAssetsDir, "routing_mode", rm)
		}

		reload := func(users []auth.User) {
			b, err := config.BuildBridgeXRayJSON(spec, users, strat, xrayLogLevel)
			if err != nil {
				log.Error("build bridge config", "err", err)
				return
			}
			if err := runner.Reload(b); err != nil {
				log.Error("xray reload", "err", err)
				return
			}
			log.Info("xray config reloaded", "users", len(users))
		}

		// Database is required for user storage.
		if spec.Database == nil || spec.Database.DSN == "" {
			log.Error("bridge requires database.dsn in spec (configure with ultra-install -db-host)")
			os.Exit(1)
		}
		database, err := db.Open(ctx, spec.Database.DSN)
		if err != nil {
			log.Error("open database", "err", err)
			os.Exit(1)
		}
		defer database.Close()
		log.Info("database connected", "dsn_prefix", dsnPrefix(spec.Database.DSN))

		userRepo := db.NewUserRepo(database)
		dbMgr, err := auth.NewDBManager(userRepo, reload, log)
		if err != nil {
			log.Error("db user manager", "err", err)
			os.Exit(1)
		}
		var mgr auth.UserManager = dbMgr

		tRepo := db.NewTrafficRepo(database)
		var trafficRepo adminapi.TrafficQuerier = tRepo

		// Start traffic stats collector when spec.Stats is set.
		if spec.Stats != nil {
			interval := time.Duration(spec.Stats.CollectIntervalSeconds) * time.Second
			if interval <= 0 {
				interval = 60 * time.Second
			}
			collector := stats.New(runner, tRepo, mgr, interval, log)
			collector.Start()
			defer collector.Close()
			log.Info("traffic stats collector started", "interval", interval)
		}

		if spec.SplitRoutingEnabled() {
			registerSplitRoutingUSR1(log, reload, mgr)
		}

		users := mgr.List()
		if len(users) == 0 && *adminToken == "" {
			log.Error(
				"bridge has no users and Admin API is disabled (empty -admin-token and ULTRA_RELAY_ADMIN_TOKEN); set a token and use POST /v1/users",
			)
			os.Exit(1)
		}
		if len(users) == 0 {
			log.Warn("no client records yet; create one with POST /v1/users on the Admin API")
		}
		// Admin API must listen before the first Xray reload: reload with geo can take many seconds;
		// systemd Type=simple marks the unit started immediately, so install-time relay-check would race.
		if *adminToken == "" {
			log.Warn("Admin API disabled: set -admin-token or ULTRA_RELAY_ADMIN_TOKEN to enable user provisioning on loopback")
		} else {
			srv, err := adminapi.NewServer(spec.AdminListen, *adminToken, mgr, trafficRepo, spec, log)
			if err != nil {
				log.Error("admin api", "err", err)
				os.Exit(1)
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Error("admin server", "err", err)
				}
			}()
			go func() {
				<-ctx.Done()
				_ = srv.Shutdown()
			}()
		}

		reload(users)

	case config.RoleExit:
		b, err := config.BuildExitXRayJSON(spec, strat, xrayLogLevel)
		if err != nil {
			log.Error("build exit config", "err", err)
			os.Exit(1)
		}
		if err := runner.StartJSON(b); err != nil {
			log.Error("start xray", "err", err)
			os.Exit(1)
		}
		log.Info("exit node xray started")

	default:
		log.Error("unknown role", "role", spec.Role)
		os.Exit(1)
	}

	<-ctx.Done()
	log.Info("shutting down")
	_ = runner.Close()
	wg.Wait()
}

// dsnPrefix returns the scheme+host portion of a DSN for safe logging (no password).
func dsnPrefix(dsn string) string {
	for i, c := range dsn {
		if c == '@' {
			// Find the last '@' to handle passwords containing '@'
			last := strings.LastIndexByte(dsn, '@')
			return dsn[last+1:]
		}
		_ = i
	}
	return dsn
}
