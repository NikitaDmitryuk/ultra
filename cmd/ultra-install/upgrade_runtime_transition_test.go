package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/installplan"
)

func TestRuntimeTransitionNativeExactBindingApplyAndRollback(t *testing.T) {
	for _, change := range []struct {
		name   string
		update func(*runtimeHostRequest)
	}{
		{"tunnel", func(r *runtimeHostRequest) { r.Features.Transport = "splithttp"; r.Features.SplitHTTPPath = "/changed" }},
		{"listener", func(r *runtimeHostRequest) { r.Bridge.VLESSPort = 7444; r.Bridge.AdminListen = "127.0.0.1:8444" }},
		{"tls-policy", func(r *runtimeHostRequest) { r.Features.GenerateExitTLS = true }},
	} {
		t.Run(change.name, func(t *testing.T) {
			store, request := runtimeHostFixture(t)
			request.Bridge.PublicHost = "vpn.example.com"
			change.update(&request)
			input := runtimeProbeInput{Request: request, Action: "prepare"}
			before := []runtimeHostImage{}
			for _, name := range runtimeHostFiles {
				image, err := store.image(store.path(name))
				if err != nil {
					t.Fatal(err)
				}
				before = append(before, image)
			}
			probe, err := inspectRuntimeHost(store, input)
			if err != nil {
				t.Fatal(err)
			}
			if len(probe.Transitions) == 0 || probe.EffectsPlan == nil {
				t.Fatal("transition lost public effect plan")
			}
			if _, err = runtimeHostTransport(store, input); err == nil {
				t.Fatal("uncheckpointed transition accepted")
			}
			bound := input
			bound.Action = ""
			bound.BotActive = false
			binding := map[string]any{"version": 1, "state": "prepared", "binding_sha256": runtimeHostDigest(bound), "plan": probe.EffectsPlan}
			raw, _ := json.Marshal(binding)
			path, _ := store.journalPath(request.Transaction)
			if err := os.WriteFile(strings.TrimSuffix(path, ".json")+".effects.json", raw, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err = runtimeHostTransport(store, input); err != nil {
				t.Fatal("checkpointed native prepare", err)
			}
			input.Action = "apply"
			if _, err = runtimeHostTransport(store, input); err != nil {
				t.Fatal(err)
			}
			input.Action = "status"
			status, err := runtimeHostTransport(store, input)
			if err != nil || status.EffectsPlan == nil {
				t.Fatal("replay lost exact effect plan", err)
			}
			input.Action = "rollback"
			if _, err = runtimeHostTransport(store, input); err != nil {
				t.Fatal(err)
			}
			for index, name := range runtimeHostFiles {
				image, err := store.image(store.path(name))
				if err != nil || !runtimeHostImagesEqual(before[index], image) {
					t.Fatal("rollback did not restore exact native file", err)
				}
			}
		})
	}
}

func TestRuntimeTransitionPlanRestrictsExposureAndFixedTLSPaths(t *testing.T) {
	input := runtimeProbeInput{Request: runtimeHostRequest{Role: config.RoleBridge}}
	spec := config.Spec{Role: config.RoleBridge, VLESSPort: 7443, AdminListen: "0.0.0.0:8443"}
	raw, _ := json.Marshal(spec)
	if _, err := buildRuntimeTransitionPlan(input, raw, []installplan.RuntimeTransitionKind{installplan.RuntimeTransitionListener}); err == nil {
		t.Fatal("new public admin exposure accepted")
	}
	spec.AdminListen = "127.0.0.1:8444"
	spec.BotTelegramProxy = &config.BotTelegramProxySpec{Enabled: true, ListenAddress: "0.0.0.0", Port: 10809}
	raw, _ = json.Marshal(spec)
	if _, err := buildRuntimeTransitionPlan(input, raw, []installplan.RuntimeTransitionKind{installplan.RuntimeTransitionListener}); err == nil {
		t.Fatal("public bot exposure accepted")
	}
	input.Request.Role = config.RoleExit
	spec.Role = config.RoleExit
	spec.ExitCertPaths = config.CertPaths{CertFile: "/arbitrary/cert", KeyFile: "/arbitrary/key"}
	raw, _ = json.Marshal(spec)
	if _, err := buildRuntimeTransitionPlan(input, raw, []installplan.RuntimeTransitionKind{installplan.RuntimeTransitionTLS}); err == nil {
		t.Fatal("arbitrary TLS paths accepted")
	}
}

func TestRuntimeTransitionEffectAuthorizationRejectsPlanAndRequestDrift(t *testing.T) {
	store, request := runtimeHostFixture(t)
	request.Bridge.PublicHost = "vpn.example.com"
	request.Bridge.VLESSPort = 7444
	input := runtimeProbeInput{Request: request}
	probe, err := inspectRuntimeHost(store, input)
	if err != nil {
		t.Fatal(err)
	}
	binding := map[string]any{"version": 1, "state": "prepared", "binding_sha256": runtimeHostDigest(input), "plan": probe.EffectsPlan}
	raw, _ := json.Marshal(binding)
	path, _ := store.journalPath(request.Transaction)
	effectPath := strings.TrimSuffix(path, ".json") + ".effects.json"
	if err := os.WriteFile(effectPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if !store.authorizedRuntimeTransitions(input, probe.Transitions, probe.EffectsPlan) {
		t.Fatal("exact plan rejected")
	}
	altered := *probe.EffectsPlan
	altered.Ports = []int{9999}
	if store.authorizedRuntimeTransitions(input, probe.Transitions, &altered) {
		t.Fatal("different firewall target authorized")
	}
	input.Request.Features.LogLevel = "other"
	if store.authorizedRuntimeTransitions(input, probe.Transitions, probe.EffectsPlan) {
		t.Fatal("changed native request authorized")
	}
	if err := os.Chmod(effectPath, 0644); err != nil {
		t.Fatal(err)
	}
	input.Request.Features.LogLevel = request.Features.LogLevel
	if store.authorizedRuntimeTransitions(input, probe.Transitions, probe.EffectsPlan) {
		t.Fatal("public effect checkpoint authorized")
	}
}

func TestRuntimeTunnelPortRequiresAuthoritativeDBCheckpoint(t *testing.T) {
	for _, role := range []config.Role{config.RoleBridge, config.RoleExit} {
		prior := config.Spec{Role: role, VLESSPort: 9443, Exit: config.ExitTunnelSpec{Port: 9443}}
		desired := prior
		if role == config.RoleExit {
			desired.VLESSPort = 9444
		} else {
			desired.Exit.Port = 9444
		}
		before, _ := json.Marshal(prior)
		after, _ := json.Marshal(desired)
		_, err := buildRuntimeTransitionPlan(runtimeProbeInput{Request: runtimeHostRequest{Role: role}}, after, []installplan.RuntimeTransitionKind{installplan.RuntimeTransitionTunnel, installplan.RuntimeTransitionListener}, before)
		if err == nil || !strings.Contains(err.Error(), "tunnel_port_db_checkpoint_required") {
			t.Fatal("DB-backed port delta accepted without bridge CAS journal", err)
		}
	}
}
