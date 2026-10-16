package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	ansibleassets "github.com/NikitaDmitryuk/ultra/deploy/ansible"
	"github.com/NikitaDmitryuk/ultra/internal/config"
)

// All bytes below are synthetic. The separate fence suite verifies the crypto,
// systemd drain and checkpoint producer; these tests exercise its native consumer.
func managedTLSRuntimeFixture(t *testing.T) (runtimeHostStore, runtimeHostRequest) {
	t.Helper()
	s, r := runtimeHostFixture(t)
	r.Role, r.Node = config.RoleExit, "primary"
	r.Exits[0].DialAddr = r.Exits[0].SSHHost
	r.Features.MainExitDomain = "tunnel.example.com"
	r.Features.SplitHTTPHost = r.Features.MainExitDomain
	r.Features.SplitHTTPPath = "/ultra-xhttp"
	r.Features.Preset, r.Features.Transport = "standard", "splithttp"
	spec := config.Spec{
		SchemaVersion:      config.CurrentSpecSchemaVersion,
		Role:               config.RoleExit,
		VLESSPort:          9443,
		MimicPreset:        "standard",
		TunnelTransport:    config.TunnelTransportSplitHTTP,
		TunnelTLSProvision: config.TunnelTLSACME,
		SplithttpHost:      r.Features.MainExitDomain,
		SplithttpPath:      r.Features.SplitHTTPPath,
		Exit:               config.ExitTunnelSpec{TunnelUUID: "11111111-1111-1111-1111-111111111111"},
		ExitCertPaths:      config.CertPaths{CertFile: "/etc/ultra-relay/fullchain.pem", KeyFile: "/etc/ultra-relay/privkey.pem"},
	}
	spec.SplitHTTPTLS.ServerName = r.Features.MainExitDomain
	spec.SplitHTTPTLS.SNIMode = "send"
	raw, _ := json.Marshal(spec)
	if err := os.WriteFile(s.path(runtimeHostFiles[0]), raw, 0640); err != nil {
		t.Fatal(err)
	}
	desired, _ := runtimeHostDesiredIdentity(r)
	sum := sha256.Sum256([]byte(spec.Exit.TunnelUUID))
	r.Proof = &runtimeHostExitProof{
		Node:                 r.Node,
		SSHHost:              r.Exits[0].SSHHost,
		DesiredIdentity:      desired,
		TunnelIdentityDigest: fmt.Sprintf("%x", sum),
	}
	installed, _ := runtimeHostInstalledIdentity(raw)
	baseline, _ := json.Marshal(runtimeHostAttestation{desired, installed})
	if err := os.WriteFile(s.path(runtimeHostIdentityFile), baseline, 0600); err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte, mode os.FileMode) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(s.path(name)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(s.path(name), raw, mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"control.lock", "pair.lock"} {
		write(managedTunnelState+"/"+name, nil, 0600)
	}
	for _, name := range []string{"certbot.service", "certbot.timer"} {
		path := s.path("etc/systemd/system/" + name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("/dev/null", path); err != nil {
			t.Fatal(err)
		}
	}
	hook, _ := ansibleassets.Bundle.ReadFile("roles/tunnel_certificate/templates/deploy-certificate.sh.j2")
	hook = []byte(strings.ReplaceAll(string(hook), "{{ ultra_tunnel_domain }}", r.Features.MainExitDomain))
	write("etc/letsencrypt/renewal-hooks/deploy/ultra-tunnel", hook, 0700)
	write("etc/ultra-relay/fullchain.pem", []byte("synthetic-certificate"), 0600)
	write("etc/ultra-relay/privkey.pem", []byte("synthetic-private-key"), 0600)
	journal := managedTunnelJournal{Version: 1, State: "frozen"}
	journal.Request.Transaction, journal.Request.Domain = r.Transaction, r.Features.MainExitDomain
	journal.Request.RuntimeRequestSHA, journal.Request.ReleaseSHA = runtimeHostDigest(r), strings.Repeat("a", 64)
	request, _ := json.Marshal(journal.Request)
	journal.RequestJSON = string(request)
	journal.HookSHA, _ = managedTunnelHookSHA(r.Features.MainExitDomain)
	journal.Binding = managedTunnelBinding(journal.RequestJSON, journal.HookSHA)
	encoded, _ := json.Marshal(journal)
	write(managedTunnelState+"/journal.json", encoded, 0600)
	write(managedTunnelState+"/blocked", []byte(journal.Binding), 0600)
	images := map[string]any{}
	for _, name := range []string{"/etc/ultra-relay/fullchain.pem", "/etc/ultra-relay/privkey.pem", "/etc/letsencrypt/renewal-hooks/deploy/ultra-tunnel"} {
		img, err := s.image(s.path(name))
		if err != nil {
			t.Fatal(err)
		}
		images[name] = map[string]any{"data": img.Data, "mode": img.Mode, "uid": img.UID, "gid": img.GID}
	}
	encoded, _ = json.Marshal(map[string]any{"version": 1, "binding": journal.Binding, "closure": map[string]any{"images": images}})
	write(managedTunnelState+"/preservation-"+journal.Binding+".json", encoded, 0600)
	return s, r
}

func TestManagedTLSNativePrepareApplyRollbackRetryPreservesPair(t *testing.T) {
	s, r := managedTLSRuntimeFixture(t)
	before, _ := os.ReadFile(s.path(runtimeHostFiles[0]))
	for _, action := range []string{"prepare", "prepare", "apply", "apply", "status", "rollback", "rollback"} {
		result, err := runtimeHostTransport(s, runtimeProbeInput{Request: r, Action: action})
		if err != nil || !result.Verified || !result.ManagedTLSReady {
			t.Fatalf("%s: %+v %v", action, result, err)
		}
		if err := s.managedTunnelAuthority(r); err != nil {
			t.Fatalf("pair/hook changed after %s: %v", action, err)
		}
	}
	after, _ := os.ReadFile(s.path(runtimeHostFiles[0]))
	if !bytes.Equal(before, after) {
		t.Fatal("rollback lost original specification bytes")
	}
}

func TestManagedTLSNativeRejectsDriftBeforeMutation(t *testing.T) {
	for _, change := range []string{"generation", "domain", "request", "pair", "marker", "mask", "checkpoint", "lock"} {
		t.Run(change, func(t *testing.T) {
			s, r := managedTLSRuntimeFixture(t)
			before, _ := os.ReadFile(s.path(runtimeHostFiles[0]))
			switch change {
			case "generation":
				r.Transaction += "-next"
			case "domain":
				r.Features.MainExitDomain = "other.example.com"
			case "request":
				r.Features.DisableDOH = true
			case "pair":
				_ = os.WriteFile(s.path("etc/ultra-relay/privkey.pem"), []byte("foreign"), 0600)
			case "marker":
				_ = os.WriteFile(s.path(managedTunnelState+"/blocked"), []byte("foreign"), 0600)
			case "mask":
				_ = os.Remove(s.path("etc/systemd/system/certbot.timer"))
			case "checkpoint":
				entries, _ := filepath.Glob(s.path(managedTunnelState + "/preservation-*.json"))
				_ = os.WriteFile(entries[0], []byte("{}"), 0600)
			case "lock":
				fd, err := syscall.Open(s.path(managedTunnelState+"/pair.lock"), syscall.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = syscall.Close(fd) }()
				if err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := runtimeHostTransport(s, runtimeProbeInput{Request: r, Action: "prepare"}); err == nil {
				t.Fatal("unproven identity accepted")
			}
			after, _ := os.ReadFile(s.path(runtimeHostFiles[0]))
			if !bytes.Equal(before, after) {
				t.Fatal("rejection mutated spec")
			}
			path, _ := s.journalPath(r.Transaction)
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("rejection created native journal")
			}
		})
	}
}

func TestManagedTLSNativeMissingPairOnlyPermitsRecoveryStatus(t *testing.T) {
	s, r := managedTLSRuntimeFixture(t)
	if _, err := runtimeHostTransport(s, runtimeProbeInput{Request: r, Action: "prepare"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.path("etc/ultra-relay/privkey.pem")); err != nil {
		t.Fatal(err)
	}
	result, err := runtimeHostTransport(s, runtimeProbeInput{Request: r, Action: "status"})
	if err != nil || !result.ManagedTLSRestorable || result.ManagedTLSReady {
		t.Fatalf("status: %+v %v", result, err)
	}
	for _, action := range []string{"prepare", "apply", "rollback"} {
		if _, err := runtimeHostTransport(s, runtimeProbeInput{Request: r, Action: action}); err == nil {
			t.Fatalf("%s accepted before pair restoration", action)
		}
	}
}
