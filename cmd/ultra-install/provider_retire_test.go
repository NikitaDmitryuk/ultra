package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func bridgeReimageFleetFixture(t *testing.T) (retainedPrimaryRebuildInput, []bridgeReimageFleetRow) {
	in := retainedRebuildFixture(t)
	in.BridgeOnly = true
	in.RetainedExit = retainedBridgeExitFixture()
	return in, []bridgeReimageFleetRow{
		{Kind: "exit", ID: "00000000-0000-0000-0000-000000000001", Address: "192.0.2.2", Port: 443, Enabled: true},
		{
			Kind:    "exit",
			ID:      "00000000-0000-0000-0000-000000000002",
			Address: "192.0.2.20",
			Port:    443,
			Enabled: true,
			Pin:     strings.Repeat("a", 64),
		},
		{
			Kind:           "cloud_operation",
			ID:             "00000000-0000-0000-0000-000000000003",
			State:          "ready",
			Phase:          "ready",
			ExitID:         "00000000-0000-0000-0000-000000000002",
			InstanceID:     "instance-test",
			OccupiesSlot:   true,
			InstallAttempt: "1",
		},
	}
}
func retirementFixture(t *testing.T) providerRetirementRequest {
	in, fleet := bridgeReimageFleetFixture(t)
	raw, _ := json.Marshal(fleet)
	deletion, _ := json.Marshal(
		providerDeleteReceipt{
			providerDeleteIntent{
				"ultra-provider-delete-intent-v1",
				"instance-test",
				"192.0.2.20",
				strings.Repeat("a", 64),
				strings.Repeat("b", 64),
			},
			"provider-instance-absent",
			1,
		},
	)
	request, err := providerRetirementPlan(in, retainedReconcileEvidence{}, deletion, raw)
	if err != nil {
		t.Fatal(err)
	}
	return request
}
func TestProviderRetirementExactScope(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong-address", "main-exit", "missing-operation", "ready-disabled", "unknown-operation", "extra-exit", "duplicate-instance"} {
		t.Run(scenario, func(t *testing.T) {
			in, fleet := bridgeReimageFleetFixture(t)
			deletion := providerDeleteReceipt{
				providerDeleteIntent{
					"ultra-provider-delete-intent-v1",
					"instance-test",
					"192.0.2.20",
					strings.Repeat("a", 64),
					strings.Repeat("b", 64),
				},
				"provider-instance-absent",
				1,
			}
			switch scenario {
			case "wrong-address":
				deletion.Intent.Address = "192.0.2.21"
			case "main-exit":
				fleet[2].ExitID = fleet[0].ID
			case "missing-operation":
				fleet = fleet[:2]
			case "ready-disabled":
				fleet[1].Enabled = false
			case "unknown-operation":
				fleet[2].State = "unknown"
			case "extra-exit":
				fleet = append(
					fleet,
					bridgeReimageFleetRow{Kind: "exit", ID: "00000000-0000-0000-0000-000000000004", Address: "192.0.2.50", Port: 443},
				)
			case "duplicate-instance":
				extra := fleet[2]
				extra.ID = "00000000-0000-0000-0000-000000000004"
				fleet = append(fleet, extra)
			}
			d, _ := json.Marshal(deletion)
			f, _ := json.Marshal(fleet)
			_, err := providerRetirementPlan(in, retainedReconcileEvidence{}, d, f)
			if (err == nil) != (scenario == "valid") {
				t.Fatalf("scope %s: %v", scenario, err)
			}
		})
	}
}

// This starts a dedicated ephemeral PostgreSQL cluster, never DATABASE_URL or
// db.Open. It executes the real transactional SQL, including lost-ack resume.
func TestProviderRetirementTransaction(t *testing.T) {
	for _, name := range []string{"initdb", "pg_ctl", "psql", "python3"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skip(name + " unavailable")
		}
	}
	root, err := os.MkdirTemp("/tmp", "upr-")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(root) }()
	data := filepath.Join(root, "data")
	if raw, err := exec.Command("initdb", "-D", data, "-A", "trust", "--no-locale").CombinedOutput(); err != nil {
		t.Fatalf("isolated initdb: %v %s", err, raw)
	}
	if raw, err := exec.Command("pg_ctl", "-D", data, "-l", filepath.Join(root, "log"), "-o", "-k "+root+" -c listen_addresses='' -c fsync=off", "-w", "start").CombinedOutput(); err != nil {
		log, _ := os.ReadFile(filepath.Join(root, "log"))
		t.Fatalf("isolated postgres start: %v %s %s", err, raw, log)
	}
	defer func() { _ = exec.Command("pg_ctl", "-D", data, "-m", "immediate", "-w", "stop").Run() }()
	env := append(os.Environ(), "PGHOST="+root, "PGDATABASE=postgres")
	sql := func(query string) string {
		t.Helper()
		cmd := exec.Command("psql", "--no-psqlrc", "-qAt", "-v", "ON_ERROR_STOP=1", "-d", "postgres", "-c", query)
		cmd.Env = env
		raw, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("isolated SQL: %v %s", e, raw)
		}
		return strings.TrimSpace(string(raw))
	}
	sql(`CREATE TABLE schema_migrations(version bigint);INSERT INTO schema_migrations VALUES(1),(2);
 CREATE TABLE exit_nodes(id uuid PRIMARY KEY,address text,port integer,enabled boolean,pinned_peer_cert_sha256 text);
 CREATE TABLE cloud_operations(id uuid PRIMARY KEY,state text,body jsonb,occupies_slot boolean);
 CREATE TABLE vpn_locations(id uuid PRIMARY KEY,exit_id uuid,published boolean);
 CREATE TABLE cloud_operation_events(id bigserial,operation_id uuid,phase text,outcome text,code text);
 CREATE TABLE protected_users(id integer,unchanged text);INSERT INTO protected_users VALUES(1,'preserve');`)
	var primary retainedPrimaryIdentity
	if json.Unmarshal(
		[]byte(
			sql(
				`SELECT json_build_object('system_identifier',(SELECT system_identifier::text FROM pg_control_system()),'database','postgres','database_oid',(SELECT oid::bigint FROM pg_database WHERE datname='postgres'),'migration_versions','1,2')`,
			),
		),
		&primary,
	) != nil {
		t.Fatal("identity")
	}
	setup := func() {
		sql(`TRUNCATE exit_nodes,cloud_operations,vpn_locations,cloud_operation_events;
 INSERT INTO exit_nodes VALUES('00000000-0000-0000-0000-000000000001','192.0.2.2',443,true,''),('00000000-0000-0000-0000-000000000002','192.0.2.20',443,true,repeat('a',64));
 INSERT INTO cloud_operations VALUES('00000000-0000-0000-0000-000000000003','ready','{"state":"ready","phase":"ready","exit_id":"00000000-0000-0000-0000-000000000002","instance_id":"instance-test","install_attempt":1,"charged":true,"preserved":"history"}',true);
 INSERT INTO vpn_locations VALUES('00000000-0000-0000-0000-000000000011','00000000-0000-0000-0000-000000000002',true),('00000000-0000-0000-0000-000000000012','00000000-0000-0000-0000-000000000001',true);`)
	}
	run := func(r providerRetirementRequest) ([]byte, error) {
		raw, _ := json.Marshal(r)
		program := strings.ReplaceAll(providerRetirementRemote, "'runuser','-u','postgres','--',", "")
		cmd := exec.Command("python3", "-c", program, "postgres", base64.StdEncoding.EncodeToString(raw))
		cmd.Env = env
		return cmd.CombinedOutput()
	}
	for _, scenario := range []string{"success-resume", "wrong-primary", "wrong-schema", "changed-fleet", "busy-worker", "exit-count-mismatch", "lost-ack-conflict"} {
		t.Run(scenario, func(t *testing.T) {
			setup()
			r := retirementFixture(t)
			r.Primary = primary
			switch scenario {
			case "wrong-primary":
				r.Primary.SystemIdentifier = "wrong"
			case "wrong-schema":
				r.Primary.MigrationVersions = "1"
			case "changed-fleet":
				r.Fleet[1].Address = "192.0.2.99"
			}
			if scenario == "exit-count-mismatch" {
				sql(`CREATE FUNCTION reject_retirement_update() RETURNS trigger LANGUAGE plpgsql AS $$BEGIN RETURN NULL; END$$;
                    CREATE TRIGGER reject_retirement_update BEFORE UPDATE ON exit_nodes FOR EACH ROW EXECUTE FUNCTION reject_retirement_update();`)
				defer sql("DROP TRIGGER reject_retirement_update ON exit_nodes; DROP FUNCTION reject_retirement_update()")
			}
			if scenario == "busy-worker" {
				conn, err := pgx.Connect(context.Background(), "host="+root+" dbname=postgres sslmode=disable")
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = conn.Close(context.Background()) }()
				if _, err = conn.Exec(context.Background(), "SELECT pg_advisory_lock(817365006)"); err != nil {
					t.Fatal(err)
				}
			}
			raw, e := run(r)
			success := scenario == "success-resume" || scenario == "lost-ack-conflict"
			if (e == nil) != success {
				t.Fatalf("transaction: %v %s", e, raw)
			}
			if !success {
				if sql("SELECT state||':'||occupies_slot::text FROM cloud_operations") != "ready:true" ||
					sql("SELECT count(*) FROM exit_nodes WHERE enabled") != "2" ||
					sql("SELECT count(*) FROM cloud_operation_events") != "0" {
					t.Fatal("failure mutated state")
				}
				return
			}
			if sql("SELECT body->>'preserved' FROM cloud_operations") != "history" || sql("SELECT count(*) FROM exit_nodes") != "2" ||
				sql("SELECT count(*) FROM protected_users WHERE unchanged='preserve'") != "1" ||
				sql("SELECT count(*) FROM vpn_locations WHERE published") != "1" {
				t.Fatal("unrelated rows changed")
			}
			if scenario == "lost-ack-conflict" {
				r.Binding = strings.Repeat("f", 64)
				if _, e = run(r); e == nil {
					t.Fatal("foreign resume accepted")
				}
				return
			}
			resumed, e := run(r)
			if e != nil || string(raw) != string(resumed) {
				t.Fatalf("lost-ack resume: %v %s", e, resumed)
			}
			if sql("SELECT count(*) FROM cloud_operation_events") != "1" {
				t.Fatal("resume repeated write")
			}
		})
	}
}
