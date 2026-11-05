package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/xtls/xray-core/core"
	"golang.org/x/sys/unix"
)

func TestReplacementPingCommandReceiptProcess(t *testing.T) {
	mode := os.Getenv("ULTRA_TEST_PING_RECEIPT_PROCESS")
	if mode == "" {
		return
	}
	if mode == "invalid-request" {
		os.Args = []string{"ultra-install", "replacement-exit-ping-probe"}
		main()
		os.Exit(92)
	}
	if mode == "dup-failure" {
		_ = unix.Close(1)
	}
	if mode == "redirect-failure" {
		_ = unix.Close(2)
	}
	called := false
	err := withReplacementPingReceipt(func(output io.Writer) error {
		called = true
		if mode != "cold-config" {
			return fmt.Errorf("unexpected callback")
		}
		file := output.(*os.File)
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
		if err != nil || flags&unix.FD_CLOEXEC == 0 {
			return fmt.Errorf("receipt descriptor is not close-on-exec")
		}
		// Build the actual production bridge's non-dev freedom outbound. The
		// dependency logs its domainStrategy migration before loglevel=none is
		// applied. No prior core instance may warm up its process-global logger.
		spec := &config.Spec{
			Role: config.RoleBridge, ExitPing: true, SplitRouting: config.BoolPtr(false),
			TunnelTransport: config.TunnelTransportSplitHTTP, TunnelTLSProvision: config.TunnelTLSSelfSigned,
			SplithttpPath: "/fixture", SplithttpHost: "example.com",
			SplitHTTPTLS: config.SplitHTTPTLSSpec{ServerName: "example.com"},
		}
		strategy, err := mimic.New("apijson")
		if err != nil {
			return err
		}
		node := exits.Node{
			ID: "a6844f19-48ce-445a-bfda-3e8bfa108c18", Address: "192.0.2.10", Port: 443,
			TunnelUUID: "de9cb0f8-6a24-4e4c-9b9c-a3bc75edc3ac", Enabled: true,
			PinnedPeerCertSHA256: strings.Repeat("ab", 32),
		}
		data, err := config.BuildBridgeXRayJSON(spec, nil, []exits.Node{node}, node.ID, strategy, "none")
		if err != nil {
			return err
		}
		var cfg map[string]any
		if err = json.Unmarshal(data, &cfg); err != nil {
			return err
		}
		cfg["inbounds"] = []any{} // Parse only: no listener, connection or core startup.
		data, err = json.Marshal(cfg)
		if err != nil {
			return err
		}
		if _, err = core.LoadConfig("json", bytes.NewReader(data)); err != nil {
			return err
		}
		// The parent acknowledges the real asynchronous dependency warning on
		// stderr. This avoids sleeps and guarantees it was emitted before exit.
		var acknowledgment [1]byte
		if _, err = io.ReadFull(os.Stdin, acknowledgment[:]); err != nil {
			return err
		}
		_, err = fmt.Fprintln(output, `{"verified":true,"count":1,"mode":"isolated"}`)
		return err
	})
	if mode == "cold-config" && err == nil {
		if _, err := fmt.Fprintln(os.Stdout, "late dependency diagnostic"); err != nil {
			os.Exit(94)
		}
		os.Exit(0)
	}
	if mode != "cold-config" && err != nil && !called {
		os.Exit(17)
	}
	fmt.Fprintln(os.Stderr, "receipt fixture failed")
	os.Exit(93)
}

func TestReplacementPingCommandColdXrayReceipt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReplacementPingCommandReceiptProcess$")
	command.Env = append(os.Environ(), "ULTRA_TEST_PING_RECEIPT_PROCESS=cold-config")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	command.Stdout = &stdout
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	var diagnostics strings.Builder
	warning := false
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		line := scanner.Text()
		diagnostics.WriteString(line + "\n")
		if !warning && strings.Contains(line, "freedom.domainStrategy") && strings.Contains(line, "deprecated") {
			warning = true
			_, _ = stdin.Write([]byte{1})
			_ = stdin.Close()
		}
	}
	if err = command.Wait(); err != nil {
		t.Fatalf("cold process: %v, stderr: %s", err, diagnostics.String())
	}
	if err = scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if !warning || !strings.Contains(diagnostics.String(), "late dependency diagnostic") {
		t.Fatalf("dependency diagnostics missing from stderr: %s", diagnostics.String())
	}
	if got, want := stdout.String(), "{\"verified\":true,\"count\":1,\"mode\":\"isolated\"}\n"; got != want {
		t.Fatalf("receipt stdout: %q", got)
	}
}

func TestReplacementPingCommandFailuresHaveNoReceipt(t *testing.T) {
	for _, mode := range []string{"invalid-request", "dup-failure", "redirect-failure"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestReplacementPingCommandReceiptProcess$")
			command.Env = append(os.Environ(), "ULTRA_TEST_PING_RECEIPT_PROCESS="+mode)
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			err := command.Run()
			if err == nil || stdout.Len() != 0 {
				t.Fatalf("failed command emitted receipt or succeeded: %v %q", err, stdout.String())
			}
			if mode != "invalid-request" && command.ProcessState.ExitCode() != 17 {
				t.Fatalf("descriptor failure reached callback: %v %s", err, stderr.String())
			}
		})
	}
}
