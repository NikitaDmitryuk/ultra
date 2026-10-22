package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
)

type fakeDeleteProvider struct {
	present   bool
	ip        string
	deletes   int
	getErr    error
	deleteErr error
	listErr   error
}

func TestProviderDeleteCLIPublishesAbsentReceiptAndResumesWithoutRedispatch(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name string, raw []byte) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	secret := write("secrets", []byte("ULTRA_VULTR_API_KEY=fixture-only\n"))
	config := write("install.config", []byte(strings.Join([]string{
		"INSTALL_SCHEMA_VERSION=2", "BRIDGE_IP=192.0.2.1", "MAIN_EXIT_IP=192.0.2.2", "BOT_DOMAIN=sync.example.com", "VPN_DOMAIN=edge.example.com", "VLESS_PORT=24443", "ACME_EMAIL=owner@example.com", "PUBLIC_XHTTP_PATH=/connect", "DNS_PROVIDER=vultr", "DNS_ZONE=example.com", "ULTRA_AUTOMATION_VERSION=v2.1", "ULTRA_AUTOMATION_RELEASE_DIR=/release", "ULTRA_AUTOMATION_AGE_RECIPIENT=age1fixture", "ULTRA_AUTOMATION_BRIDGE_PROVIDER=a", "ULTRA_AUTOMATION_KNOWN_HOSTS_FILE=/pins", "ULTRA_AUTOMATION_ADMIN_TELEGRAM_ID=123", `ULTRA_AUTOMATION_STATIC_NODES=[{"name":"main","address":"192.0.2.2","provider":"a"}]`, "SECRETS_ENV_FILE=" + secret,
	}, "\n")))
	ids := write("ids.json", []byte(`["target"]`))
	raw, _ := json.Marshal(
		providerCensusReceipt{
			Protocol:   "ultra-provider-census-v1",
			ObservedAt: time.Now().Unix(),
			Requested:  []providerCensusInstance{{ID: "target", Address: "192.0.2.3", Present: true}},
		},
	)
	census := write("census.json", raw)
	receipt := filepath.Join(root, "receipt.json")
	args := []string{
		"--config",
		config,
		"--census",
		census,
		"--instance-id-file",
		ids,
		"--expected-address",
		"192.0.2.3",
		"--receipt",
		receipt,
		"--execute",
	}
	p := &fakeDeleteProvider{present: true, ip: "192.0.2.3"}
	factory := func(key string) deleteCensusProvider {
		if key != "fixture-only" {
			t.Fatal("wrong resolver")
		}
		return p
	}
	if err := runProviderDeleteWithProvider(args, io.Discard, factory); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(receipt)
	if err != nil {
		t.Fatal("successful DELETE lost its receipt", err)
	}
	var saved providerDeleteReceipt
	if json.Unmarshal(first, &saved) != nil || saved.Result != "provider-instance-absent" {
		t.Fatal("invalid receipt")
	}
	if err = runProviderDeleteWithProvider(args, io.Discard, factory); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(receipt)
	if string(first) != string(second) || p.deletes != 1 {
		t.Fatal("resume changed receipt or repeated DELETE")
	}
	// A crash after provider absence but before publication must also recover.
	if err = os.Remove(receipt); err != nil {
		t.Fatal(err)
	}
	if err = runProviderDeleteWithProvider(args, io.Discard, factory); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(receipt); err != nil || p.deletes != 1 {
		t.Fatal("lost-receipt resume did not recover safely")
	}
}

func (p *fakeDeleteProvider) Instances(context.Context) ([]cloud.Instance, error) {
	if p.listErr != nil {
		return nil, p.listErr
	}
	if p.present {
		return []cloud.Instance{{ID: "target", IP: p.ip}}, nil
	}
	return nil, nil
}
func (p *fakeDeleteProvider) Get(context.Context, string) (cloud.Instance, error) {
	if p.getErr != nil {
		return cloud.Instance{}, p.getErr
	}
	if p.present {
		return cloud.Instance{ID: "target", IP: p.ip}, nil
	}
	return cloud.Instance{}, cloud.APIError{Status: 404}
}
func (p *fakeDeleteProvider) Delete(context.Context, string) error {
	p.deletes++
	if p.deleteErr != nil {
		return p.deleteErr
	}
	p.present = false
	return nil
}

func TestProviderDeleteExactTargetAndUncertainReplay(t *testing.T) {
	intent := providerDeleteIntent{InstanceID: "target", Address: "192.0.2.2"}
	for _, scenario := range []string{"success", "changed-ip", "resume-present", "resume-absent", "lost-response", "forbidden", "list-failed"} {
		t.Run(scenario, func(t *testing.T) {
			p := &fakeDeleteProvider{present: true, ip: intent.Address}
			resume := false
			switch scenario {
			case "changed-ip":
				p.ip = "192.0.2.3"
			case "resume-present":
				resume = true
			case "resume-absent":
				resume = true
				p.present = false
			case "lost-response":
				p.deleteErr = errors.New("secret remote response")
			case "forbidden":
				p.getErr = cloud.APIError{Status: 403}
			case "list-failed":
				p.listErr = errors.New("unavailable")
			}
			err := deleteObservedProviderInstance(context.Background(), p, intent, resume)
			if (err == nil) != (scenario == "success" || scenario == "resume-absent") {
				t.Fatalf("wrong result %v", err)
			}
			want := 0
			if scenario == "success" || scenario == "lost-response" || scenario == "list-failed" {
				want = 1
			}
			if p.deletes != want {
				t.Fatalf("unexpected mutation count %d", p.deletes)
			}
			if scenario == "lost-response" {
				p.present = false
				p.deleteErr = nil
				if err = deleteObservedProviderInstance(context.Background(), p, intent, true); err != nil || p.deletes != 1 {
					t.Fatal("lost acknowledgment redispatched")
				}
			}
		})
	}
}
