package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"github.com/google/uuid"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func runReplacementPingLease(args []string) error {
	if os.Geteuid() != 0 || len(args) != 2 || len(args[0]) != 64 {
		return errors.New("replacement_exit_ping_lease_invalid")
	}
	for _, c := range args[0] {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return errors.New("replacement_exit_ping_lease_invalid")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	client := deployansible.Client{Socket: "/run/ultra-ansible/controller.sock"}
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte(args[0])).String()
	switch args[1] {
	case "ready":
		return drainLocalLifecycle(ctx)
	case "acquire":
		if err := client.Lifecycle(ctx, id, "applying"); err != nil {
			return errors.New("replacement_exit_ping_lease_unavailable")
		}
		if err := drainLocalLifecycle(ctx); err != nil {
			return errors.New("replacement_exit_ping_drain_failed")
		}
		return nil
	case "release":
		if err := client.Lifecycle(ctx, id, "released"); err != nil {
			return errors.New("replacement_exit_ping_lease_release_failed")
		}
		return nil
	default:
		return errors.New("replacement_exit_ping_lease_invalid")
	}
}

// Root-only internal command: an isolated synthetic credential and listener,
// never db.Open, never application user credentials and never a public API.
func runReplacementPingProbe(args []string, output io.Writer) error {
	fail := errors.New("replacement_exit_ping_isolated_probe_failed")
	if os.Geteuid() != 0 || len(args) != 2 || len(args[1]) != 64 {
		return fail
	}
	path := filepath.Clean(args[0])
	if filepath.Dir(path) != "/var/lib/ultra-replacement-ping/"+args[1] || !strings.HasPrefix(filepath.Base(path), "probe-") {
		return fail
	}
	for parent := path; parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
			return fail
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 65536 {
		return fail
	}
	var request replacementPingRollout
	if json.Unmarshal(raw, &request) != nil || request.Binding != args[1] || len(request.Nodes) != 1 {
		return fail
	}
	spec, err := config.LoadSpec("/etc/ultra-relay/spec.json")
	if err != nil || spec.Role != config.RoleBridge || !spec.ExitPing || spec.HappExitPing {
		return fail
	}
	if spec.GeoAssetsDir != "" {
		if err = os.Setenv("XRAY_LOCATION_ASSET", spec.GeoAssetsDir); err != nil {
			return fail
		}
	}
	if err = probeReplacementPing(context.Background(), spec, request.Nodes[0]); err != nil {
		return fail
	}
	_, err = fmt.Fprintln(output, `{"verified":true,"count":1,"mode":"isolated"}`)
	return err
}

func probeReplacementPing(ctx context.Context, spec *config.Spec, node replacementPingRoute) error {
	if net.ParseIP(node.Address) == nil || node.Port < 1 || node.Port > 65535 || uuid.Validate(node.TunnelUUID) != nil {
		return errors.New("invalid_probe_binding")
	}
	strategy, err := mimic.New(spec.MimicPreset)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err = listener.Close(); err != nil {
		return err
	}
	user := auth.User{UUID: uuid.NewString(), EffectiveExitID: node.ID}
	s := *spec
	s.Stats = nil
	s.Database = nil
	data, err := config.BuildBridgeXRayJSON(
		&s,
		[]auth.User{user},
		[]exits.Node{
			{
				ID:                   node.ID,
				Address:              node.Address,
				Port:                 node.Port,
				TunnelUUID:           node.TunnelUUID,
				PinnedPeerCertSHA256: node.Pin,
				Enabled:              true,
			},
		},
		node.ID,
		strategy,
		"none",
	)
	if err != nil {
		return err
	}
	var cfg map[string]any
	if err = json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	// Replace every production listener with exactly one loopback VLESS listener.
	// Outbounds and reserved-target routing are the candidate bridge builder's.
	cfg["inbounds"] = []any{
		map[string]any{
			"listen":         "127.0.0.1",
			"port":           port,
			"protocol":       "vless",
			"settings":       map[string]any{"decryption": "none", "clients": []any{map[string]any{"id": user.UUID}}},
			"streamSettings": map[string]any{"network": "tcp", "security": "none"},
		},
	}
	data, err = json.Marshal(cfg)
	if err != nil {
		return err
	}
	var bridge, client proxy.Runner
	if err = bridge.StartJSON(data); err != nil {
		return err
	}
	defer func() { _ = bridge.Close() }()
	data, err = json.Marshal(
		map[string]any{
			"log": map[string]any{"loglevel": "none"},
			"outbounds": []any{
				map[string]any{
					"protocol": "vless",
					"settings": map[string]any{
						"vnext": []any{
							map[string]any{
								"address": "127.0.0.1",
								"port":    port,
								"users":   []any{map[string]any{"id": user.UUID, "encryption": "none"}},
							},
						},
					},
					"streamSettings": map[string]any{"network": "tcp", "security": "none"},
				},
			},
		},
	)
	if err != nil {
		return err
	}
	if err = client.StartJSON(data); err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			d, e := xnet.ParseDestination(network + ":" + address)
			if e != nil {
				return nil, e
			}
			return core.Dial(ctx, client.Instance(), d)
		},
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{
		Transport:     transport,
		Timeout:       8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("probe_redirect_refused") },
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		req, e := http.NewRequestWithContext(ctx, method, config.ExitPingURL, nil)
		if e != nil {
			return e
		}
		resp, e := httpClient.Do(req)
		if e != nil {
			return errors.New("probe_unreachable")
		}
		body, e := io.ReadAll(io.LimitReader(resp.Body, 1))
		_ = resp.Body.Close()
		if e != nil || resp.StatusCode != http.StatusNoContent || len(body) != 0 {
			return errors.New("probe_response_invalid")
		}
	}
	return nil
}
