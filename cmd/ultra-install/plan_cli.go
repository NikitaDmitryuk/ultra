package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func handlePlanSubcommand(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "plan":
		runPlanCommand(args[1:])
	case "doctor":
		runDoctorCommand(args[1:])
	case "doctor-remote":
		runDoctorRemoteCommand(args[1:])
	case "render":
		runRenderCommand(args[1:])
	case "apply":
		runApplyPlanCommand(args[1:])
	case "apply-remote":
		runApplyRemoteCommand(args[1:])
	default:
		return false
	}
	return true
}

func runPlanCommand(args []string) {
	fs := flag.NewFlagSet("ultra-install plan", flag.ExitOnError)
	configPath := fs.String("config", "install.config", "legacy install.config path")
	out := fs.String("out", "", "write install-plan JSON to path")
	format := fs.String("format", "human", "human or json")
	_ = fs.Parse(args)

	p, err := installplan.LoadLegacyEnvConfig(*configPath)
	exitOnErr("plan", err)
	exitOnErr("plan validate", installplan.ValidatePlan(p))
	writePlanOutput(p, *out, *format)
}

func runDoctorCommand(args []string) {
	fs := flag.NewFlagSet("ultra-install doctor", flag.ExitOnError)
	planPath := fs.String("plan", "", "install-plan JSON path")
	format := fs.String("format", "human", "human or json")
	network := fs.Bool("network", false, "run DNS/TCP checks")
	envRoot := fs.String("env-root", ".", "root for relative bot env path")
	_ = fs.Parse(args)

	p := readPlanOrExit(*planPath)
	opts := installplan.DoctorOptions{EnvRoot: *envRoot}
	if *network {
		opts = installplan.NetworkDoctorOptions(3 * time.Second)
		opts.EnvRoot = *envRoot
	}
	report := installplan.Doctor(context.Background(), p, opts)
	if *format == "json" {
		writeJSON(os.Stdout, report)
	} else {
		if report.OK {
			fmt.Println("doctor: OK")
		}
		for _, issue := range report.Issues {
			fmt.Printf("%s [%s] %s", issue.Severity, issue.Code, issue.Message)
			if issue.Node != "" {
				fmt.Printf(" (%s)", issue.Node)
			}
			fmt.Println()
		}
	}
	if !report.OK {
		os.Exit(1)
	}
}

func runDoctorRemoteCommand(args []string) {
	fs := flag.NewFlagSet("ultra-install doctor-remote", flag.ExitOnError)
	format := fs.String("format", "human", "human or json")
	_ = fs.Parse(args)
	report := installplan.RemoteHostDoctor(context.Background())
	if *format == "json" {
		writeJSON(os.Stdout, report)
	} else {
		if report.OK {
			fmt.Println("doctor-remote: OK")
		}
		for _, issue := range report.Issues {
			fmt.Printf("%s [%s] %s\n", issue.Severity, issue.Code, issue.Message)
		}
	}
	if !report.OK {
		os.Exit(1)
	}
}

func runRenderCommand(args []string) {
	fs := flag.NewFlagSet("ultra-install render", flag.ExitOnError)
	planPath := fs.String("plan", "", "install-plan JSON path")
	out := fs.String("out", "", "artifact output directory")
	_ = fs.Parse(args)
	if strings.TrimSpace(*out) == "" {
		fmt.Fprintln(os.Stderr, "render: -out is required")
		os.Exit(2)
	}
	p := readPlanOrExit(*planPath)
	ds, err := installplan.RenderDesiredState(p)
	exitOnErr("render", err)
	exitOnErr("render mkdir", os.MkdirAll(*out, 0o700))
	exitOnErr("render bridge spec", os.WriteFile(filepath.Join(*out, "bridge-spec.json"), ds.BridgeSpec, 0o600))
	bootstrap, err := installplan.MarshalBootstrap(ds.Bootstrap)
	exitOnErr("render bootstrap", err)
	exitOnErr("render bootstrap", os.WriteFile(filepath.Join(*out, exits.BootstrapFileName), bootstrap, 0o600))
	exitOnErr("render bridge env", os.WriteFile(filepath.Join(*out, "bridge.env"), []byte(ds.BridgeEnv), 0o600))
	names := sortedKeys(ds.ExitSpecs)
	for _, name := range names {
		exitOnErr("render exit spec", os.WriteFile(filepath.Join(*out, "exit-"+sanitizeName(name)+"-spec.json"), ds.ExitSpecs[name], 0o600))
		exitOnErr("render exit env", os.WriteFile(filepath.Join(*out, "exit-"+sanitizeName(name)+".env"), []byte(ds.ExitEnvs[name]), 0o600))
	}
	summary := map[string]any{
		"admin_token":    ds.AdminToken,
		"tunnel_uuids":   ds.TunnelUUIDs,
		"splithttp_host": ds.SplitHTTPHost,
		"splithttp_path": ds.SplitHTTPPath,
	}
	b, err := json.MarshalIndent(summary, "", "  ")
	exitOnErr("render summary", err)
	exitOnErr("render summary", os.WriteFile(filepath.Join(*out, "install-summary.json"), b, 0o600))
	fmt.Println("rendered install artifacts:", *out)
}

func runApplyPlanCommand(args []string) {
	fs := flag.NewFlagSet("ultra-install apply", flag.ExitOnError)
	planPath := fs.String("plan", "", "install-plan JSON path")
	secretsPath := fs.String("secrets", "", "secrets env file path; overrides plan.secrets.env_file")
	format := fs.String("format", "human", "human or jsonl")
	_ = fs.Parse(args)
	p := readPlanOrExit(*planPath)
	if strings.TrimSpace(*secretsPath) != "" {
		p.Secrets.EnvFile = *secretsPath
	}
	exitOnErr("apply validate", installplan.ValidatePlan(p))
	emitInstallEvent(*format, installplan.EventStep, "", "starting plan apply engine", "")
	applyPlanN(p, *format)
}

func runApplyRemoteCommand(args []string) {
	fs := flag.NewFlagSet("ultra-install apply-remote", flag.ExitOnError)
	planPath := fs.String("plan", "", "install-plan JSON path on this server")
	secretsPath := fs.String("secrets", "", "secrets env file path already available on this server")
	releaseDir := fs.String("release-dir", "/opt/ultra/current", "directory containing ultra-relay and ultra-bot release binaries")
	format := fs.String("format", "human", "human or jsonl")
	_ = fs.Parse(args)
	p := readPlanOrExit(*planPath)
	if strings.TrimSpace(*secretsPath) != "" {
		p.Secrets.EnvFile = *secretsPath
	}
	exitOnErr("apply-remote validate", installplan.ValidatePlan(p))
	emitInstallEvent(*format, installplan.EventStep, "", "starting remote apply", "")
	applyRemotePlan(p, *releaseDir, *format)
}

func readPlanOrExit(path string) *installplan.InstallPlan {
	if strings.TrimSpace(path) == "" {
		fmt.Fprintln(os.Stderr, "-plan is required")
		os.Exit(2)
	}
	data, err := os.ReadFile(path)
	exitOnErr("read plan", err)
	var p installplan.InstallPlan
	exitOnErr("parse plan", json.Unmarshal(data, &p))
	exitOnErr("validate plan", installplan.ValidatePlan(&p))
	return &p
}

func writePlanOutput(p *installplan.InstallPlan, out, format string) {
	if format != "human" && format != "json" {
		fmt.Fprintln(os.Stderr, "plan: -format must be human or json")
		os.Exit(2)
	}
	b, err := json.MarshalIndent(p, "", "  ")
	exitOnErr("marshal plan", err)
	if out != "" {
		exitOnErr("write plan", os.WriteFile(out, b, 0o600))
		if format == "human" {
			fmt.Println("wrote install plan:", out)
			return
		}
	}
	fmt.Println(string(b))
}

func emitInstallEvent(format string, kind installplan.EventKind, code, message, node string) {
	ev := installplan.InstallEvent{Time: time.Now().UTC(), Kind: kind, Code: code, Message: message, Node: node}
	if format == "jsonl" {
		b, _ := json.Marshal(ev)
		fmt.Println(string(b))
		return
	}
	if code != "" {
		fmt.Printf("%s [%s] %s\n", kind, code, message)
	} else {
		fmt.Printf("%s: %s\n", kind, message)
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "node"
	}
	var b strings.Builder
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('-')
		}
	}
	return b.String()
}

func writeJSON(f *os.File, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	exitOnErr("json", err)
	_, err = fmt.Fprintln(f, string(b))
	exitOnErr("json write", err)
}

func exitOnErr(prefix string, err error) {
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "%s: %v\n", prefix, err)
	os.Exit(1)
}
