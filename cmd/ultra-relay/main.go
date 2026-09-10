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
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/adminapi"
	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/firewall"
	"github.com/NikitaDmitryuk/ultra/internal/loglevel"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"github.com/NikitaDmitryuk/ultra/internal/stats"
	"github.com/NikitaDmitryuk/ultra/internal/subscriptionkey"

	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/NikitaDmitryuk/ultra/internal/rtc"
	"github.com/NikitaDmitryuk/ultra/internal/rtcingress"
)

func main() {
	checkConfig := flag.Bool("check-config", false, "validate spec and RTC secret files without starting services or opening the database")
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

	if *checkConfig {
		for _, binding := range spec.RTC {
			if !spec.RTCService.Enabled || !binding.Enabled {
				continue
			}
			for _, name := range []string{binding.KeyFile, binding.PasswordFile} {
				if _, err := rtc.ReadSecret(name); err != nil {
					log.Error("RTC secret validation failed")
					os.Exit(1)
				}
			}
		}
		return
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

		var mgr auth.UserManager
		var exitMgr *exits.Manager
		var exitSelector *exits.Selector
		var reloadBridge func([]auth.User)
		var applyBridge func([]auth.User, string) error

		exitSelector = exits.NewSelector(func(ctx context.Context, n exits.Node) exits.Health {
			return runner.ProbeExit(ctx, n, spec.HealthTargets())
		})

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

		exitRepo := db.NewExitNodeRepo(database)
		bootstrapPath := filepath.Join(filepath.Dir(*specPath), exits.BootstrapFileName)
		if err := exitRepo.Bootstrap(ctx, spec, bootstrapPath); err != nil {
			log.Error("bootstrap exit nodes", "err", err)
			os.Exit(1)
		}

		exitMgr, err = exits.NewManager(exitRepo, func(_ []exits.Node) {
			if applyBridge != nil {
				_ = applyBridge(nil, "exit configuration")
			}
		}, log)
		if err != nil {
			log.Error("exit manager", "err", err)
			os.Exit(1)
		}

		userRepo := db.NewUserRepo(database)
		if spec.SOCKS5 != nil && spec.SOCKS5.Enabled {
			userRepo.SetSOCKS5BridgePorts(spec.SOCKS5.PortRangeStart, spec.SOCKS5.PortRangeEnd, spec.SOCKS5.Port)
		}
		fw := firewall.New()

		var reloadMu sync.Mutex
		applications := &auth.RouteApplications{}
		applyBridge = func(users []auth.User, reason string) (applyErr error) {
			c, cancel := context.WithTimeout(ctx, 20*time.Second)
			defer cancel()
			ctx := c
			reloadMu.Lock()
			defer reloadMu.Unlock()
			started := time.Now()
			defer func() {
				applications.Finish(applyErr)
				if applyErr != nil {
					log.Warn("route application failed", "reason", reason, "code", "route_apply_failed", "duration", time.Since(started))
				}
			}()
			quotaRepo := db.NewQuotaRepo(database)
			quotaSnapshot, e := quotaRepo.Snapshot(ctx)
			if e != nil {
				return e
			}
			routeRepo := db.NewRouteRepo(database)
			if e := routeRepo.PrepareManual(ctx); e != nil {
				return e
			}
			if mgr != nil {
				if refresh, ok := mgr.(interface{ Refresh(context.Context) error }); ok {
					if e := refresh.Refresh(ctx); e != nil {
						return e
					}
				}
				users = mgr.List()
			}
			exitNodes := exitMgr.List()
			enabled := exits.FilterEnabled(exitNodes)
			activeID := exitSelector.ActiveID()
			activeStillEnabled := false
			for _, n := range enabled {
				if n.ID == activeID {
					activeStillEnabled = true
					break
				}
			}
			if activeID == "" || !activeStillEnabled {
				active, _ := exits.SelectActive(enabled, nil)
				activeID = active.ID
				exitSelector.SetActiveID(activeID)
			}
			health := exitSelector.HealthSnapshot()
			users = auth.ExpandRoutes(users)
			users = applyEffectiveUserExits(users, enabled, activeID, health)
			transitions := map[[2]string]int{}
			for _, u := range users {
				old := applications.Status(u.UUID).EffectiveExit
				if old != u.EffectiveExitID {
					transitions[[2]string{old, u.EffectiveExitID}]++
				}
			}
			applications.Begin(users)
			b, err := config.BuildBridgeXRayJSON(spec, users, exitNodes, activeID, strat, xrayLogLevel)
			if err != nil {
				log.Error("build bridge config", "err", err)
				return err
			}
			before := runner.Status().Count
			if err := runner.ReloadReason(b, reason); err != nil {
				log.Error("xray reload", "err", err)
				return err
			}
			applications.Finish(nil)
			for route, count := range transitions {
				log.Info("route transition applied", "from_exit", route[0], "to_exit", route[1], "profiles", count, "revision", applications.Status("").Revision, "reason", reason, "duration", time.Since(started))
			}
			if after := runner.Status(); after.Count != before {
				log.Info("xray config reloaded", "users", len(users), "active_exit", activeID, "reload_count", after.Count, "reason", after.Reason, "at", after.At, "duration", time.Since(started))
			}
			if e := quotaRepo.Acknowledge(ctx, quotaSnapshot); e != nil {
				return e
			}
			if e := routeRepo.AppliedManual(ctx); e != nil {
				return e
			}
			if refresh, ok := mgr.(interface{ Refresh(context.Context) error }); ok {
				return refresh.Refresh(ctx)
			}
			return nil
		}

		reloadBridge = func(users []auth.User) { _ = applyBridge(users, "users, preferences or routing configuration") }
		dbMgr, err := auth.NewDBManager(userRepo, reloadBridge, fw, log)
		if err != nil {
			log.Error("db user manager", "err", err)
			os.Exit(1)
		}
		dbMgr.ApplyChange = func(users []auth.User) error { return applyBridge(users, "users or preferences") }
		mgr = dbMgr

		tRepo := db.NewTrafficRepo(database)
		var trafficRepo adminapi.TrafficQuerier = tRepo

		// Start traffic stats collector when spec.Stats is set.
		if spec.Stats != nil {
			interval := time.Duration(spec.Stats.CollectIntervalSeconds) * time.Second
			if interval <= 0 {
				interval = 30 * time.Second
			}
			interval = min(30*time.Second, max(10*time.Second, interval))
			collector := stats.New(runner, tRepo, mgr, interval, log)
			collector.Start()
			defer collector.Close()
			log.Info("traffic stats collector started", "interval", interval)
		}

		if spec.SplitRoutingEnabled() {
			registerSplitRoutingUSR1(log, reloadBridge, mgr)
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
			statPeek := func(key string) int64 { return runner.PeekCounter(key) }
			srv, err := adminapi.NewServer(spec.AdminListen, *adminToken, mgr, trafficRepo, spec, exitMgr, exitSelector, nil, log, statPeek)
			if err != nil {
				log.Error("admin api", "err", err)
				os.Exit(1)
			}
			srv.ReloadStatus = runner.Status
			srv.RouteStatus = applications.Status
			configureCloud(ctx, &wg, srv, database, spec, exitMgr, func(c context.Context) error { return applyBridge(nil, "cloud route change") }, dbMgr.Refresh, log)
			keys, keyErr := subscriptionkey.Load(os.Getenv("ULTRA_SUBSCRIPTION_ENCRYPTION_KEY_FILE"))
			if keyErr != nil {
				log.Warn("subscription recovery and issuance unavailable: encryption key not configured")
			}
			if spec.RTCService.Enabled {
				content, e := rtc.LoadContent(spec.RTCService.ContentFile)
				rtcKeys, rtcKeyErr := subscriptionkey.Load(spec.RTCService.EncryptionKeyFile)
				if e != nil || rtcKeyErr != nil {
					log.Error("RTC private configuration unavailable")
					os.Exit(1)
				}
				service := rtcingress.New(db.NewRTCRepo(database), rtcKeys, content, runner.DialRTC, spec.RTCService.Socket)
				if e = service.Initialize(ctx, spec.RTCService.GatewayPort, spec.RTC); e != nil {
					log.Error("RTC initialization failed")
					os.Exit(1)
				}
				srv.RTC = service
				wg.Add(1)
				go func() { defer wg.Done(); service.Run(ctx) }()
			}
			subscriptions := db.NewSubscriptionRepo(database, keys)
			srv.Subscriptions = subscriptions
			srv.Members = &adminapi.MemberService{Repo: db.NewMemberRepo(database), Subscriptions: subscriptions, Apply: func(c context.Context) error {
				if e := dbMgr.Refresh(c); e != nil {
					return e
				}
				return applyBridge(nil, "member access change")
			}}
			wg.Add(1)
			go func() { defer wg.Done(); srv.Members.Run(ctx) }()
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

		_ = applyBridge(mgr.List(), "startup")
		go exitSelector.RunWorker(ctx, 10*time.Second, func(c context.Context) ([]exits.Node, error) {
			if runner.Status().Error != "" || applications.Pending() {
				_ = applyBridge(nil, "retry failed reload")
			}
			return exitMgr.ListEnabled(), nil
		}, func() { _ = applyBridge(nil, "exit health selection") })

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

func applyEffectiveUserExits(users []auth.User, enabled []exits.Node, activeID string, health map[string]exits.Health) []auth.User {
	if len(users) == 0 {
		return users
	}
	out := append([]auth.User(nil), users...)
	for i := range out {
		out[i].EffectiveExitID = out[i].SelectExit(enabled, activeID, health)
	}
	return out
}
