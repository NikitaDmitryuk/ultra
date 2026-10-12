// Command ultra-relay runs the routing core in-process and serves one spec-defined role (bridge or exit).
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"github.com/xtls/xray-core/core"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/loglevel"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"

	_ "github.com/xtls/xray-core/main/distro/all"
)

func main() {
	transportPath := flag.String("transport-spec", "", "isolated experimental transport spec (no database or workers)")
	checkOnly := flag.Bool("check", false, "validate spec and certificate without starting services")
	runtimeState := flag.String("runtime-state", "/var/lib/ultra-relay/runtime.db", "private durable relay state and traffic journal")
	cacheOnly := flag.Bool("cache-only", false, "emergency bridge startup from existing accounting state; no database or control workers")
	drainOnly := flag.Bool("drain-journal", false, "flush a stopped bridge's durable traffic journal to PostgreSQL and exit")
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
	if *cacheOnly && (*drainOnly || *checkOnly || *transportPath != "") {
		fmt.Fprintln(os.Stderr, "cache-only cannot be combined with drain-journal, check, or transport-spec")
		os.Exit(2)
	}

	slogLvl, xrayLogLevel, err := loglevel.ParseRelayLogLevel(*logLevelFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ultra-relay:", err)
		os.Exit(2)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slogLvl}))
	log.Info("ultra-relay starting", "log_level", *logLevelFlag, "xray_loglevel", xrayLogLevel)

	if *transportPath != "" {
		if *specPath != "" || *drainOnly {
			log.Error("spec and transport-spec are mutually exclusive")
			os.Exit(2)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := runTransport(ctx, *transportPath, *checkOnly); err != nil {
			log.Error("transport failed", "err", err)
			os.Exit(1)
		}
		return
	}
	if *specPath == "" {
		log.Error("missing -spec")
		os.Exit(2)
	}
	spec, err := config.LoadSpec(*specPath)
	if err != nil {
		log.Error("load spec", "err", err)
		os.Exit(1)
	}
	if *cacheOnly && spec.Role != config.RoleBridge {
		log.Error("cache-only requires a bridge spec")
		os.Exit(2)
	}
	if *drainOnly {
		if *checkOnly || spec.Role != config.RoleBridge {
			log.Error("drain-journal requires a bridge spec and cannot be combined with check")
			os.Exit(2)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := drainJournal(ctx, spec, *runtimeState); err != nil {
			log.Error("journal drain failed; keep relay stopped and retain the journal")
			os.Exit(1)
		}
		log.Info("journal drained and committed; retain the state file for compatible upgrades")
		return
	}

	strat, err := mimic.New(spec.MimicPreset)
	if err != nil {
		log.Error("mimic preset", "err", err)
		os.Exit(1)
	}

	if *checkOnly {
		if spec.Role == config.RoleBridge && spec.SplitRoutingEnabled() {
			if err := os.Setenv("XRAY_LOCATION_ASSET", spec.GeoAssetsDir); err != nil {
				log.Error("set XRAY_LOCATION_ASSET", "err", err)
				os.Exit(1)
			}
		}
		var data []byte
		if spec.Role == config.RoleBridge {
			data, err = config.BuildBridgeXRayJSON(spec, nil, nil, "", strat, xrayLogLevel)
		} else {
			data, err = config.BuildExitXRayJSON(spec, strat, xrayLogLevel)
		}
		if err == nil {
			_, err = core.LoadConfig("json", bytes.NewReader(data))
		}
		if err != nil {
			log.Error("Xray configuration validation failed")
			os.Exit(1)
		}
		return
	}

	runner := new(proxy.Runner)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch spec.Role {
	case config.RoleBridge:
		if err := runBridge(ctx, spec, *specPath, *runtimeState, *adminToken, runner, strat, xrayLogLevel, log, bridgeOptions{CacheOnly: *cacheOnly}); err != nil {
			log.Error("bridge stopped", "err", err)
			os.Exit(1)
		}

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
