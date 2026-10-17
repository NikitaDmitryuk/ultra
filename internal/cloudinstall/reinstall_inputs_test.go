package cloudinstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

func TestReinstallAttemptSnapshotsCurrentInputsAndReusesThem(t *testing.T) {
	root := t.TempDir()
	p := &Provisioner{StateDir: root, Binary: filepath.Join(root, "current-relay")}
	op := &cloud.Operation{ID: "operation", InstallAttempt: 1, Reinstall: true}
	if err := os.Mkdir(filepath.Join(root, op.ID), 0700); err != nil {
		t.Fatal(err)
	}
	request := deployansible.ExitRequest{
		Host: "192.0.2.2", User: "root", BridgeIPv4: "192.0.2.1",
		Identity: filepath.Join(
			root,
			"identity",
		), KnownHosts: filepath.Join(root, op.ID, "known_hosts"),
		Spec: config.Spec{
			VLESSPort:     8443,
			SplithttpPath: "/old",
			Exit:          config.ExitTunnelSpec{TunnelUUID: "same-tunnel"},
		},
	}
	for _, file := range []string{p.Binary, request.Identity, request.KnownHosts} {
		if err := os.WriteFile(file, []byte("original"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	binary, saved, err := p.reinstallInputs(op, request)
	if err != nil {
		t.Fatal(err)
	}
	jobID, err := configurationAttemptJobID(op.ID, op.InstallAttempt, binary, saved)
	if err != nil {
		t.Fatal(err)
	}
	op.ReinstallJobID = jobID // Simulate the persisted reservation and a controller still running.
	for _, file := range []string{p.Binary, request.Identity, request.KnownHosts} {
		if err := os.WriteFile(file, []byte("new-input"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	request.Spec.SplithttpPath = "/new"
	request.BridgeIPv4 = "192.0.2.3"
	p = &Provisioner{StateDir: root, Binary: p.Binary} // Worker restart.
	repeatedBinary, repeated, err := p.reinstallInputs(op, request)
	if err != nil {
		t.Fatal(err)
	}
	repeatedID, err := configurationAttemptJobID(op.ID, op.InstallAttempt, repeatedBinary, repeated)
	if err != nil || repeatedID != jobID || repeated.Spec.SplithttpPath != "/old" ||
		repeated.BridgeIPv4 != "192.0.2.1" {
		t.Fatalf("attempt changed after restart: %s %v %+v", repeatedID, err, repeated)
	}
	for _, file := range []string{repeatedBinary, repeated.Identity, repeated.KnownHosts} {
		if data, err := os.ReadFile(file); err != nil || string(data) != "original" {
			t.Fatalf("snapshot mutated: %s %v", file, err)
		}
	}
	op.InstallAttempt++
	op.ReinstallJobID = ""
	nextBinary, next, err := p.reinstallInputs(op, request)
	if err != nil {
		t.Fatal(err)
	}
	if next.Spec.SplithttpPath != "/new" ||
		next.Spec.Exit.TunnelUUID != saved.Spec.Exit.TunnelUUID ||
		next.Spec.VLESSPort != saved.Spec.VLESSPort {
		t.Fatal("new attempt did not refresh config while retaining tunnel identity")
	}
	if data, err := os.ReadFile(nextBinary); err != nil || string(data) != "new-input" {
		t.Fatalf("new attempt did not refresh binary: %s %v", data, err)
	}
	if err := os.WriteFile(nextBinary, []byte("tampered"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.reinstallInputs(op, request); err == nil {
		t.Fatal("modified snapshot accepted")
	}
}

func TestReservedReinstallDoesNotCreateReplacementSnapshot(t *testing.T) {
	root := t.TempDir()
	op := &cloud.Operation{ID: "operation", InstallAttempt: 3, ReinstallJobID: "running-job"}
	p := &Provisioner{StateDir: root}
	if _, _, err := p.reinstallInputs(op, deployansible.ExitRequest{}); !errors.Is(err, errReinstallSnapshotUnavailable) {
		t.Fatalf("missing legacy snapshot not classified: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, op.ID)); !os.IsNotExist(err) {
		t.Fatal("reserved inputs created")
	}
}

func TestReinstallFirewallUsesCurrentBridgeAndStoredListener(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			var rules []struct {
				Subnet string `json:"subnet"`
				Port   string `json:"port"`
			}
			server := httptest.NewServer(
				http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					switch {
					case r.URL.Path == "/firewalls":
						_, _ = w.Write(
							[]byte(
								`{"firewall_groups":[{"id":"existing","description":"ultra-operation-operation"}],"meta":{"links":{"next":""}}}`,
							),
						)
					case r.Method == http.MethodGet:
						_, _ = w.Write([]byte(`{"firewall_rules":[],"meta":{"links":{"next":""}}}`))
					case fail:
						http.Error(w, "fixture refusal", http.StatusForbidden)
					default:
						var rule struct {
							Subnet string `json:"subnet"`
							Port   string `json:"port"`
						}
						if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
							t.Error(err)
						}
						rules = append(rules, rule)
					}
				}),
			)
			defer server.Close()
			p := &Provisioner{
				API:      &cloud.Vultr{BaseURL: server.URL, HTTP: server.Client()},
				BridgeIP: "192.0.2.99", // Live state may differ from the attempt snapshot.
				Bridge:   &config.Spec{VLESSPort: 9443},
			}
			op := &cloud.Operation{ID: "operation", FirewallID: "existing"}
			err := p.reconcileReinstallFirewall(context.Background(), op, exits.Node{Port: 8443}, "192.0.2.10")
			if fail {
				if err == nil {
					t.Fatal("provider firewall failure ignored")
				}
				return
			}
			if err != nil || len(rules) != 2 || rules[0].Subnet != "192.0.2.10" ||
				rules[0].Port != "22" ||
				rules[1].Subnet != "192.0.2.10" ||
				rules[1].Port != "8443" ||
				op.FirewallID != "existing" {
				t.Fatalf("wrong firewall reconciliation: %+v %v", rules, err)
			}
		})
	}
}

type receiptConfigurer struct {
	failedAnsibleConfigurer
	terminal bool
	err      error
	jobID    string
}

func (c *receiptConfigurer) ConfigurationTerminal(_ context.Context, jobID string) (bool, error) {
	c.jobID = jobID
	return c.terminal, c.err
}

func TestLegacyReinstallReceiptReleaseRequiresTerminalProofAndCAS(t *testing.T) {
	for _, test := range []struct {
		name      string
		terminal  bool
		proofErr  error
		clearErr  error
		noReader  bool
		wantClear bool
	}{
		{name: "terminal", terminal: true, wantClear: true},
		{name: "running"},
		{name: "unconfirmed", terminal: true, proofErr: errors.New("receipt unavailable")},
		{name: "unsupported", noReader: true},
		{name: "CAS conflict", terminal: true, clearErr: cloud.ErrConflict, wantClear: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			op := &cloud.Operation{
				ID: "operation", ExitID: "operation", InstanceID: "same-vps", InstallAttempt: 3,
				ReinstallJobID: "legacy-job", ReinstallTarget: "192.0.2.2",
			}
			before := *op
			p := &Provisioner{StateDir: t.TempDir()}
			_, _, snapshotErr := p.reinstallInputs(op, deployansible.ExitRequest{})
			if !errors.Is(snapshotErr, errReinstallSnapshotUnavailable) {
				t.Fatalf("legacy receipt not classified: %v", snapshotErr)
			}
			reader := &receiptConfigurer{terminal: test.terminal, err: test.proofErr}
			var configurer ExitConfigurer = reader
			if test.noReader {
				configurer = failedAnsibleConfigurer{}
			}
			cleared := false
			err := releaseReinstall(context.Background(), op, configurer, func(_ context.Context, current *cloud.Operation) error {
				cleared = true
				if !reflect.DeepEqual(*current, before) {
					t.Fatal("reservation identity changed before CAS")
				}
				if test.clearErr != nil {
					return test.clearErr
				}
				current.ReinstallJobID, current.ReinstallTarget = "", ""
				return nil
			})
			if cleared != test.wantClear {
				t.Fatalf("CAS called = %t, want %t", cleared, test.wantClear)
			}
			if !test.noReader && reader.jobID != before.ReinstallJobID {
				t.Fatal("terminal proof queried wrong receipt")
			}
			if errors.Join(snapshotErr, err) == nil {
				t.Fatal("old receipt accepted as current install success")
			}
			if test.name == "terminal" {
				before.ReinstallJobID, before.ReinstallTarget = "", ""
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unproven release accepted")
			}
			if !reflect.DeepEqual(*op, before) {
				t.Fatal("release changed attempt, VPS, or unconfirmed reservation")
			}
		})
	}
}
