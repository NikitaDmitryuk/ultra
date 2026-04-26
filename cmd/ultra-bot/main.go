// ultra-bot is the Telegram bot and Mini App server for ultra-relay administration.
//
// Secrets: only TELEGRAM_BOT_TOKEN is required from the .env file (or environment).
// ULTRA_RELAY_ADMIN_TOKEN is read from the systemd EnvironmentFile
// (/etc/ultra-relay/environment — already present after ultra-install).
// The PostgreSQL DSN is read from spec.json (database.dsn) unless overridden by ULTRA_DB_DSN.
//
// Usage:
//
//	ultra-bot [flags]
//
// Flags:
//
//	-spec            path to ultra-relay spec.json (default /etc/ultra-relay/spec.json)
//	-admin-api-url   ultra-relay Admin API URL (default http://127.0.0.1:8443)
//	-domain          public domain for Mini App HTTPS and Let's Encrypt
//	-port            HTTPS port for Mini App (default 8444)
//	-data-dir        directory for autocert cache (default /var/lib/ultra-bot)
//	-dev             disable TLS, serve plain HTTP (development only)
//	-log-level       slog level: debug, info, warn, error (default info)
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/acme/autocert"

	"github.com/NikitaDmitryuk/ultra/internal/bot"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
)

func main() {
	specFile := flag.String("spec", "/etc/ultra-relay/spec.json", "path to ultra-relay spec.json (for DB DSN)")
	adminAPIURL := flag.String("admin-api-url", "http://127.0.0.1:8443", "ultra-relay Admin API URL")
	domain := flag.String("domain", "", "public domain for Mini App HTTPS (required for Telegram Mini App)")
	port := flag.String("port", "8444", "HTTPS port for Mini App")
	certFile := flag.String("cert-file", "", "path to TLS certificate file (PEM); when set, skips autocert")
	keyFile := flag.String("key-file", "", "path to TLS private key file (PEM); when set, skips autocert")
	dataDir := flag.String("data-dir", "/var/lib/ultra-bot", "directory for autocert cache and data")
	devMode := flag.Bool("dev", false, "serve plain HTTP only (no TLS); Mini App will not work from Telegram")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn, error")
	flag.Parse()

	log := makeLogger(*logLevel)

	// ── Secrets ───────────────────────────────────────────────────────────────
	// Load .env from the working directory (only sets vars not already in environment).
	loadDotEnv(log)

	botToken := mustEnv(log, "TELEGRAM_BOT_TOKEN")

	// Admin API token: set by ultra-install in /etc/ultra-relay/environment;
	// the systemd unit includes it as an EnvironmentFile.
	adminToken := mustEnv(log, "ULTRA_RELAY_ADMIN_TOKEN")

	// DB DSN: prefer explicit env var, fall back to spec.json → database.dsn.
	dbDSN := os.Getenv("ULTRA_DB_DSN")
	if dbDSN == "" {
		spec, err := config.LoadSpec(*specFile)
		if err != nil {
			log.Error("read spec for DB DSN (set ULTRA_DB_DSN to override)", "spec", *specFile, "err", err)
			os.Exit(1)
		}
		if spec.Database == nil || spec.Database.DSN == "" {
			log.Error("spec.database.dsn is empty and ULTRA_DB_DSN is not set", "spec", *specFile)
			os.Exit(1)
		}
		dbDSN = spec.Database.DSN
	}

	// ── Database ──────────────────────────────────────────────────────────────
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	database, err := db.Open(ctx, dbDSN)
	if err != nil {
		log.Error("open database", "err", err)
		os.Exit(1)
	}
	defer database.Close()

	adminRepo := db.NewBotAdminRepo(database)
	teleRepo := db.NewTelegramRepo(database)

	// ── Mini App URL ──────────────────────────────────────────────────────────
	miniAppURL := ""
	if *domain != "" {
		scheme := "https"
		if *devMode {
			scheme = "http"
		}
		if *port == "443" || (*devMode && *port == "80") {
			miniAppURL = fmt.Sprintf("%s://%s/", scheme, *domain)
		} else {
			miniAppURL = fmt.Sprintf("%s://%s:%s/", scheme, *domain, *port)
		}
	}

	// ── Bot ───────────────────────────────────────────────────────────────────
	b, err := bot.New(botToken, *adminAPIURL, adminToken, miniAppURL, adminRepo, teleRepo, log)
	if err != nil {
		log.Error("create bot", "err", err)
		os.Exit(1)
	}
	b.StartWorkers(ctx)

	// ── HTTP server ───────────────────────────────────────────────────────────
	srv := &http.Server{Handler: b.Handler()}

	switch {
	case *devMode:
		srv.Addr = ":" + *port
		log.Info("starting HTTP server (dev mode, no TLS)", "addr", srv.Addr)
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("HTTP server", "err", err)
			}
		}()

	case *domain != "" && *certFile != "" && *keyFile != "":
		// File-based TLS (certbot / manual cert).
		srv.Addr = ":" + *port
		log.Info("starting HTTPS Mini App server (cert files)", "addr", srv.Addr, "domain", *domain, "cert", *certFile)
		go func() {
			if err := srv.ListenAndServeTLS(*certFile, *keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("HTTPS server", "err", err)
			}
		}()

	case *domain != "":
		// autocert: obtain certificate automatically via Let's Encrypt HTTP-01.
		certDir := filepath.Join(*dataDir, "certs")
		if err := os.MkdirAll(certDir, 0o700); err != nil {
			log.Error("create cert dir", "err", err)
			os.Exit(1)
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*domain),
			Cache:      autocert.DirCache(certDir),
		}
		// HTTP-01 ACME challenge on port 80 (must be reachable from the internet).
		go func() {
			acmeSrv := &http.Server{Addr: ":80", Handler: m.HTTPHandler(nil)}
			log.Info("starting ACME HTTP-01 server", "addr", ":80")
			if err := acmeSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Warn("ACME HTTP server error", "err", err)
			}
		}()
		srv.Addr = ":" + *port
		srv.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate, MinVersion: tls.VersionTLS12}
		log.Info("starting HTTPS Mini App server", "addr", srv.Addr, "domain", *domain)
		go func() {
			if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("HTTPS server", "err", err)
			}
		}()

	default:
		log.Warn("no -domain configured; Mini App HTTPS server not started; Telegram Mini App requires HTTPS")
	}

	// ── Long polling ──────────────────────────────────────────────────────────
	go func() {
		if err := b.RunPolling(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Error("Telegram polling", "err", err)
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	_ = srv.Close()
}

func mustEnv(log *slog.Logger, key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Error("required environment variable not set", "var", key)
		os.Exit(1)
	}
	return v
}

// loadDotEnv reads KEY=VALUE pairs from .env in the working directory.
// Only sets variables not already present in the environment.
func loadDotEnv(log *slog.Logger) {
	data, err := os.ReadFile(".env")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if len(v) >= 2 && ((v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'')) {
			v = v[1 : len(v)-1]
		}
		if k == "" || os.Getenv(k) != "" {
			continue
		}
		if err := os.Setenv(k, v); err != nil {
			log.Warn("setenv from .env", "key", k, "err", err)
		}
	}
}

func makeLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: l}))
}
