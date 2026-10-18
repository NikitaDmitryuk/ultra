package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
)

var rebuildTestNow = time.Unix(1800000000, 0)

func rebuildTestProof() rebuildEvidence {
	hash := func(s string) string { return digestSHA256([]byte(s)) }
	stamp := rebuildTestNow.Unix()
	return rebuildEvidence{
		Protocol: rebuildPreflightProtocol, OperationID: "11111111-1111-1111-1111-111111111111",
		OldLifecycleID: "22222222-2222-2222-2222-222222222222", OldGateSHA: hash("old gate"),
		Nonce: hash("nonce"), IssuedAt: stamp - 10, ExpiresAt: stamp + 60,
		JournalSHA: hash("{}"), ConfigSHA: hash("canonical config"), ManifestSHA: hash("{}"), Complete: true,
		Censuses: []rebuildCensus{{Provider: "provider", AccountSHA: hash("account"), InventorySHA: hash("inventory"),
			ObservedAt: stamp, PaginationComplete: true, TargetCount: 2}},
		Targets: []rebuildTarget{
			{ID: "bridge", Role: "bridge", Provider: "provider", AccountSHA: hash("account"), InstanceID: "bridge-instance",
				SSHIdentitySHA: hash("bridge key"), ObservationSHA: hash("bridge observation"), ObservedAt: stamp, WorkersFenced: true},
			{ID: "exit", Role: "exit", Provider: "provider", AccountSHA: hash("account"), InstanceID: "exit-instance",
				SSHIdentitySHA: hash("exit key"), ObservationSHA: hash("exit observation"), ObservedAt: stamp, WorkersFenced: true},
		},
		Primary: rebuildPrimary{Provider: "provider", AccountSHA: hash("account"), InstanceID: "primary-instance",
			SSHIdentitySHA: hash("primary key"), SystemIdentifier: "123456789", Database: "example_db", DatabaseOID: 16384,
			Primary: true, MigrationsSHA: hash("migrations"), DSNBindingSHA: hash("dsn selection"), ObservationSHA: hash("primary observation"),
			ObservedAt: stamp, WorkersFenced: true, AccessPolicy: "reuse-existing-authorization", AuthorizationSHA: hash("authorization")},
		Steps: []rebuildStep{{Operation: "rebuild-exits", Targets: []string{"exit"}},
			{Operation: "rebuild-bridge", Targets: []string{"bridge"}}, {Operation: "activate-bot", Targets: []string{"bridge"}}},
	}
}

func rebuildTestEnvelope(t *testing.T, proof rebuildEvidence) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(rebuildEnvelope{Protocol: rebuildPreflightProtocol, SignerID: digestSHA256(public),
		Payload: payload, Signature: ed25519.Sign(private, payload)})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestRebuildEvidenceRejectsUnsafeClaims(t *testing.T) {
	cases := map[string]func(*rebuildEvidence){
		"partial":             func(p *rebuildEvidence) { p.Complete = false },
		"pagination":          func(p *rebuildEvidence) { p.Censuses[0].PaginationComplete = false },
		"count":               func(p *rebuildEvidence) { p.Censuses[0].TargetCount++ },
		"expired":             func(p *rebuildEvidence) { p.ExpiresAt = rebuildTestNow.Unix() },
		"future":              func(p *rebuildEvidence) { p.IssuedAt = rebuildTestNow.Unix() + 1 },
		"old observation":     func(p *rebuildEvidence) { p.Targets[0].ObservedAt = p.IssuedAt - 1 },
		"long lifetime":       func(p *rebuildEvidence) { p.ExpiresAt = p.IssuedAt + 301 },
		"config binding":      func(p *rebuildEvidence) { p.ConfigSHA = p.Nonce },
		"primary replacement": func(p *rebuildEvidence) { p.Targets[0].InstanceID = p.Primary.InstanceID },
		"primary key":         func(p *rebuildEvidence) { p.Targets[0].SSHIdentitySHA = p.Primary.SSHIdentitySHA },
		"duplicate target":    func(p *rebuildEvidence) { p.Targets[1].ID = p.Targets[0].ID },
		"duplicate instance":  func(p *rebuildEvidence) { p.Targets[1].InstanceID = p.Targets[0].InstanceID },
		"duplicate key":       func(p *rebuildEvidence) { p.Targets[1].SSHIdentitySHA = p.Targets[0].SSHIdentitySHA },
		"ambiguous bridge":    func(p *rebuildEvidence) { p.Targets[1].Role = "bridge" },
		"unfenced":            func(p *rebuildEvidence) { p.Targets[1].WorkersFenced = false },
		"db host":             func(p *rebuildEvidence) { p.Steps[0].Targets = []string{"primary"} },
		"role mismatch":       func(p *rebuildEvidence) { p.Steps[0].Targets = []string{"bridge"} },
		"missing exit":        func(p *rebuildEvidence) { p.Steps[0].Targets = nil },
		"duplicate stage":     func(p *rebuildEvidence) { p.Steps[1] = p.Steps[0] },
		"secondary":           func(p *rebuildEvidence) { p.Primary.Primary = false },
		"system identity":     func(p *rebuildEvidence) { p.Primary.SystemIdentifier = "0" },
		"oid":                 func(p *rebuildEvidence) { p.Primary.DatabaseOID = 0 },
		"writers":             func(p *rebuildEvidence) { p.Primary.ActiveClients = 1 },
		"db worker":           func(p *rebuildEvidence) { p.Primary.WorkersFenced = false },
		"auth change":         func(p *rebuildEvidence) { p.Primary.AccessPolicy = "replace-authorized-keys" },
	}
	for _, operation := range []string{"bootstrap-postgres", "database-import", "restore-database", "migrate", "create-role", "create-slot", "pg-hba", "ansible-run"} {
		cases[operation] = func(p *rebuildEvidence) { p.Steps[0].Operation = operation }
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			proof := rebuildTestProof()
			change(&proof)
			original := rebuildTestProof()
			if _, err := validateRebuildEvidence(rebuildTestEnvelope(t, proof), rebuildTestNow, original.JournalSHA, original.ConfigSHA, original.ManifestSHA); err == nil {
				t.Fatal("accepted unsafe claim")
			}
		})
	}
}

func TestRebuildJSONRejectsParserAmbiguity(t *testing.T) {
	for _, raw := range []string{`{"operation":"a","operation":"b"}`, `{"operation":"a","targets":[],"delegate_to":"database"}`,
		`{"operation":"a","targets":[],"Operation":"b"}`,
		`{"operation":"a","targets":[]} {}`, `{"operation":"a","targets":[{"x":1,"x":2}]}`,
		`{"operation":"a"}`, `{"operation":"a","targets":null}`} {
		var step rebuildStep
		if err := rebuildDecode([]byte(raw), &step); err == nil {
			t.Fatalf("accepted ambiguous JSON: %s", raw)
		}
	}
	proofRaw, err := json.Marshal(rebuildTestProof())
	if err != nil {
		t.Fatal(err)
	}
	for _, alias := range []struct{ exact, conflicting string }{
		{`"complete_fleet":true`, `"complete_fleet":false,"COMPLETE_FLEET":true`},
		{`"active_clients":0`, `"active_clients":1,"ACTIVE_CLIENTS":0`},
	} {
		ambiguous := bytes.Replace(proofRaw, []byte(alias.exact), []byte(alias.conflicting), 1)
		if bytes.Equal(ambiguous, proofRaw) {
			t.Fatalf("test alias target not found: %s", alias.exact)
		}
		var proof rebuildEvidence
		if err := rebuildDecode(ambiguous, &proof); err == nil {
			t.Fatalf("accepted case-insensitive alias: %s", alias.conflicting)
		}
	}
}

func TestRebuildCLIAlwaysBlockedPreservesInputsAndRejectsReplay(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "separate-state")
	if err := os.Mkdir(state, 0700); err != nil {
		t.Fatal(err)
	}
	inputs := map[string][]byte{"proof": rebuildTestEnvelope(t, rebuildTestProof()), "operation.json": []byte("{}"),
		"install.config": []byte("canonical config"), "manifest.json": []byte("{}")}
	for name, raw := range inputs {
		if err := os.WriteFile(filepath.Join(root, name), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"preflight", "--proof", filepath.Join(root, "proof"), "--original-journal", filepath.Join(root, "operation.json"),
		"--config", filepath.Join(root, "install.config"), "--manifest", filepath.Join(root, "manifest.json"), "--state-dir", state}
	var output bytes.Buffer
	for iteration := 0; iteration < 2; iteration++ {
		output.Reset()
		if err := runRebuildNonDB(args, &output, rebuildTestNow); !errors.Is(err, errRebuildBlocked) {
			t.Fatalf("expected blocked, got %v", err)
		}
		var record rebuildPreflightRecord
		if err := json.Unmarshal(output.Bytes(), &record); err != nil {
			t.Fatal(err)
		}
		if record.State != "blocked-unverified" || record.FleetVerified || record.PrimaryVerified || record.GateReleased ||
			record.ExecutionSupported || record.PrimaryConnectivityVerified || record.BackupVerified ||
			record.FormerTargetsReimaged || record.JournalRetirementSupported ||
			len(record.Blockers) != 8 ||
			len(record.Envelope) != 0 {
			t.Fatal("untrusted signed claims became execution authority or leaked evidence", record)
		}
		for _, required := range []string{"former_target_reimage_not_verified", "independent_backup_receipt_not_verified",
			"retained_primary_connectivity_not_verified", "journal_retirement_not_implemented"} {
			found := false
			for _, blocker := range record.Blockers {
				found = found || blocker == required
			}
			if !found {
				t.Fatalf("missing safety blocker: %s", required)
			}
		}
	}
	for name, raw := range inputs {
		got, err := os.ReadFile(filepath.Join(root, name))
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("input changed: %s, %v", name, err)
		}
	}
	journalPath := filepath.Join(state, "rebuild-preflight.json")
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	proof := rebuildTestProof()
	proof.Nonce = digestSHA256([]byte("another attempt"))
	if err := os.WriteFile(filepath.Join(root, "proof"), rebuildTestEnvelope(t, proof), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runRebuildNonDB(args, io.Discard, rebuildTestNow); err == nil || errors.Is(err, errRebuildBlocked) {
		t.Fatal("changed proof reused sealed journal", err)
	}
	after, err := os.ReadFile(journalPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("replay overwrote journal", err)
	}
	for _, action := range []string{"execute", "resume", "complete", "force"} {
		if err := runRebuildNonDB([]string{action}, io.Discard, rebuildTestNow); err == nil {
			t.Fatal("execution exposed", action)
		}
	}
}

// A primary excluded from the first stage must stay excluded from every later
// stage, including bot activation. Role labels cannot turn it into a target.
func TestRebuildPrimaryExcludedFromEveryMutationStage(t *testing.T) {
	for index := range rebuildTestProof().Steps {
		t.Run(rebuildTestProof().Steps[index].Operation, func(t *testing.T) {
			proof := rebuildTestProof()
			proof.Steps[index].Targets = append(proof.Steps[index].Targets, "primary")
			if _, err := validateRebuildEvidence(rebuildTestEnvelope(t, proof), rebuildTestNow,
				proof.JournalSHA, proof.ConfigSHA, proof.ManifestSHA); err == nil {
				t.Fatal("primary admitted to mutation stage")
			}
		})
	}
	for _, role := range []string{"primary", "database", "db"} {
		t.Run(role, func(t *testing.T) {
			proof := rebuildTestProof()
			proof.Targets[1].Role = role
			if _, err := validateRebuildEvidence(rebuildTestEnvelope(t, proof), rebuildTestNow,
				proof.JournalSHA, proof.ConfigSHA, proof.ManifestSHA); err == nil {
				t.Fatal("database role admitted to rebuild targets")
			}
		})
	}
}

func TestRebuildStateFailsClosedOnCrashUnknownAndConcurrency(t *testing.T) {
	for _, artifact := range []string{".rebuild-preflight-pending", "dispatch-intent.json", "completion.json", "operation.json"} {
		t.Run(artifact, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, artifact), []byte("unknown outcome"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := persistBlockedRebuild(root, []byte("record")); err == nil {
				t.Fatal("accepted unknown checkpoint")
			}
			if _, err := os.Stat(filepath.Join(root, "rebuild-preflight.json")); !os.IsNotExist(err) {
				t.Fatal("published on unknown outcome", err)
			}
		})
	}
	root := t.TempDir()
	lock, err := os.OpenFile(filepath.Join(root, ".rebuild-preflight.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close() //nolint:errcheck
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := persistBlockedRebuild(root, []byte("record")); err == nil {
		t.Fatal("concurrent writer admitted")
	}
}

type rebuildTestTransport func(*http.Request) (*http.Response, error)

func (f rebuildTestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestRebuildProviderCollectorConsumesAllPagesAndRejectsUnknown(t *testing.T) {
	mapping := []rebuildInstanceMapping{{ID: "bridge", InstanceID: "b", Role: "bridge", Address: "192.0.2.1", OwnerTag: "owned"},
		{ID: "exit", InstanceID: "e", Role: "exit", Address: "192.0.2.2", OwnerTag: "owned"},
		{ID: "database", InstanceID: "p", Role: "primary", Address: "192.0.2.3", OwnerTag: "owned"}}
	for _, scenario := range []string{"complete", "unknown", "untagged", "missing", "duplicate", "address-drift", "provider-failure", "cursor-cycle"} {
		t.Run(scenario, func(t *testing.T) {
			calls := 0
			provider := cloud.NewVultr("synthetic-test-key")
			provider.HTTP = &http.Client{Transport: rebuildTestTransport(func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method != "GET" || request.URL.Path != "/v2/instances" || request.URL.Query().Get("per_page") != "500" {
					t.Fatal("non-inventory or mutating request", request.Method, request.URL.Path)
				}
				if scenario == "provider-failure" {
					return nil, errors.New("synthetic failure")
				}
				page := mapping[:1]
				next := "page-two"
				if calls > 1 {
					if request.URL.Query().Get("cursor") != "page-two" {
						t.Fatal("cursor missing")
					}
					page, next = mapping[1:], ""
				}
				instances := []cloud.Instance{}
				for _, entry := range page {
					instances = append(
						instances,
						cloud.Instance{
							ID:           entry.InstanceID,
							IP:           entry.Address,
							Tags:         []string{"owned"},
							Status:       "active",
							ServerStatus: "ok",
							PowerStatus:  "running",
						},
					)
				}
				if calls > 1 {
					switch scenario {
					case "unknown":
						instances = append(instances, cloud.Instance{ID: "unknown"})
					case "untagged":
						instances[0].Tags = nil
					case "missing":
						instances = instances[:1]
					case "duplicate":
						instances[1] = instances[0]
					case "address-drift":
						instances[0].IP = "192.0.2.99"
					case "cursor-cycle":
						next = "page-two"
					}
				}
				raw, err := json.Marshal(
					map[string]any{"instances": instances, "meta": map[string]any{"links": map[string]string{"next": next}}},
				)
				if err != nil {
					t.Fatal(err)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(raw)), Header: http.Header{}}, nil
			})}
			instances, err := collectRebuildProviderInventory(context.Background(), provider, mapping)
			if scenario == "complete" {
				if err != nil || len(instances) != 3 || calls != 2 {
					t.Fatalf("pagination failed: count=%d calls=%d err=%v", len(instances), calls, err)
				}
			} else if err == nil {
				t.Fatal("unsafe inventory accepted", scenario)
			}
		})
	}
}

func TestRebuildInputRejectsLinksPermissionsAndSpecialFiles(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "input")
	if err := os.WriteFile(path, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"symlink", "hardlink", "public", "fifo", "directory"} {
		t.Run(kind, func(t *testing.T) {
			candidate := filepath.Join(root, kind)
			var err error
			switch kind {
			case "symlink":
				err = os.Symlink(path, candidate)
			case "hardlink":
				err = os.Link(path, candidate)
			case "public":
				err = os.WriteFile(candidate, []byte("private"), 0644)
			case "fifo":
				err = syscall.Mkfifo(candidate, 0600)
			case "directory":
				err = os.Mkdir(candidate, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = readRebuildInput(candidate, true); err == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
}
