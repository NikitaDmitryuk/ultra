package installplan

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
)

func TestDatabasePhysicalHostFreshAndReuseProjection(t *testing.T) {
	p := completePlanFixture(LegacyValuesToPlan(map[string]string{
		"BRIDGE_IP": "192.0.2.1", "MAIN_EXIT_IP": "192.0.2.2", "DATABASE_IP": "192.0.2.40",
		"REUSE_BRIDGE_SPEC": "false", "REALITY_DEST": "example.com:443",
	}))
	fresh, err := RenderDesiredState(p)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.BridgeSpecObject.Database.PrimaryHost != "192.0.2.40" {
		t.Fatal("physical database host absent from fresh runtime")
	}
	var raw config.Spec
	if err := json.Unmarshal(fresh.BridgeSpec, &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Database.PrimaryHost != "192.0.2.40" {
		t.Fatal("physical host not serialized in installed spec")
	}
	// An older installed spec has only a tunnel DSN. Reuse adds metadata while
	// retaining the existing connection identity and password.
	fresh.BridgeSpecObject.Database.PrimaryHost = ""
	dsn := fresh.BridgeSpecObject.Database.DSN
	p.Bridge.ReuseSpec = true
	reused, err := RenderDesiredStateWithOptions(p, RenderOptions{ExistingBridge: fresh.BridgeSpecObject})
	if err != nil {
		t.Fatal(err)
	}
	if reused.BridgeSpecObject.Database.PrimaryHost != "192.0.2.40" || reused.DBDSN != dsn ||
		fresh.BridgeSpecObject.Database.PrimaryHost != "" {
		t.Fatal("reuse lost metadata, mutated its input, or changed connection identity")
	}
}

func TestDatabasePhysicalHostRuntimeProjectionPreservesDSNAndUnknownFields(t *testing.T) {
	p, opts := projectionFixture(t)
	p.Database = DatabaseConfig{Enabled: true, PrimaryHost: "192.0.2.40", Name: "ultra_db", User: "ultra"}
	doc, err := runtimeDocument(opts.ExistingBridgeJSON)
	if err != nil {
		t.Fatal(err)
	}
	database := runtimeObject(doc, "database")
	runtimeSet(database, "extension", "preserved")
	runtimeSet(doc, "database", database)
	raw, _ := json.Marshal(doc)
	projected, err := ProjectLocalRuntime(p, raw, config.RoleBridge, "")
	if err != nil {
		t.Fatal(err)
	}
	var spec config.Spec
	if err := json.Unmarshal(projected.SpecJSON, &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Database.PrimaryHost != "192.0.2.40" || spec.Database.DSN != opts.ExistingBridge.Database.DSN ||
		!bytes.Contains(projected.SpecJSON, []byte(`"extension": "preserved"`)) {
		t.Fatal("projection lost physical host or changed existing database contract")
	}
}

func TestDatabasePhysicalHostAbsentFromLegacyAdoption(t *testing.T) {
	p, opts := adoptionRenderFixture()
	ds, err := RenderDesiredStateWithOptions(p, opts)
	if err != nil {
		t.Fatal(err)
	}
	if ds.BridgeSpecObject.Database.PrimaryHost != "" || !bytes.Equal(ds.BridgeSpec, opts.ExistingBridgeJSON) {
		t.Fatal("legacy adoption invented physical database identity or changed runtime")
	}
}
