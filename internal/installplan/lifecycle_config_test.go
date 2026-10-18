package installplan

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lifecycleConfigFixture() map[string]string {
	v := canonicalFixture()
	v["REUSE_BRIDGE_SPEC"] = "false"
	v["BOT_ENABLE"] = "true"
	v["DATABASE_IP"] = "192.0.2.30"
	v["REALITY_DEST"] = "example.com:443"
	return v
}

func TestLifecycleConfigDoesNotOpenBootstrapDump(t *testing.T) {
	for _, archive := range []string{"missing", "public", "invalid"} {
		t.Run(archive, func(t *testing.T) {
			v := lifecycleConfigFixture()
			path := filepath.Join(t.TempDir(), "bootstrap.dump")
			if archive != "missing" {
				mode := os.FileMode(0600)
				if archive == "public" {
					mode = 0644
				}
				if err := os.WriteFile(path, []byte("not a custom archive"), mode); err != nil {
					t.Fatal(err)
				}
			}
			v["DATABASE_DUMP"] = path
			p, err := CanonicalLifecycleValuesToPlan(v)
			if err != nil || ValidatePlan(p) != nil {
				t.Fatalf("lifecycle rejected existing database: %v", err)
			}
			if p.Secrets.DatabaseDumpFile != "" || p.Secrets.DatabaseDumpSHA256 != "" || p.SourceValues["DATABASE_DUMP"] != "" {
				t.Fatal("archive reference retained in lifecycle inputs")
			}
			raw, err := json.Marshal(p)
			if err != nil || strings.Contains(string(raw), path) || !strings.Contains(string(raw), `"lifecycle_only":true`) {
				t.Fatalf("unsafe lifecycle serialization: %s %v", raw, err)
			}
			if v["DATABASE_DUMP"] != path {
				t.Fatal("operator configuration mutated")
			}
			if _, err := CanonicalValuesToPlan(v); err == nil {
				t.Fatal("bootstrap accepted an unavailable or invalid archive")
			}
		})
	}
}

func TestLifecycleBudgetAuthoritySurvivesProjectionAndSerialization(t *testing.T) {
	v := lifecycleConfigFixture()
	// The staged wrapper config has already removed the operator-local dump.
	p, err := CanonicalLifecycleValuesToPlan(v)
	if err != nil || ValidatePlan(p) != nil {
		t.Fatalf("existing DB budgets not authoritative: %v", err)
	}
	raw, _ := json.Marshal(p)
	var decoded InstallPlan
	if err = json.Unmarshal(raw, &decoded); err != nil || ValidatePlan(&decoded) != nil {
		t.Fatalf("lifecycle context lost: %v", err)
	}
	if ValidateBootstrapPlan(&decoded) == nil {
		t.Fatal("serialized lifecycle plan authorized bootstrap")
	}
	// A clean bootstrap without an imported database still needs real budgets.
	fresh, err := CanonicalValuesToPlan(v)
	if err != nil {
		t.Fatal(err)
	}
	if err = ValidateBootstrapPlan(fresh); err == nil || !strings.Contains(err.Error(), "explicit traffic budgets") {
		t.Fatalf("clean bootstrap budget requirement lost: %v", err)
	}
	decoded.Automation.StaticNodes[0].Budget = &StaticBudget{MonthlyBytes: 1}
	if err = ValidateBootstrapPlan(&decoded); err == nil {
		t.Fatal("explicit budgets bypassed lifecycle bootstrap rejection")
	}
}

func TestLifecycleLoaderAndBootstrapDigestStaySeparate(t *testing.T) {
	v := lifecycleConfigFixture()
	archive := filepath.Join(t.TempDir(), "bootstrap.dump")
	if err := os.WriteFile(archive, []byte("PGDMPsynthetic archive"), 0600); err != nil {
		t.Fatal(err)
	}
	v["DATABASE_DUMP"] = archive
	config := filepath.Join(t.TempDir(), "install.config")
	var text strings.Builder
	for key, value := range v {
		text.WriteString(key + "=" + value + "\n")
	}
	if err := os.WriteFile(config, []byte(text.String()), 0600); err != nil {
		t.Fatal(err)
	}
	fresh, err := LoadConfig(config)
	if err != nil || ValidateBootstrapPlan(fresh) != nil || fresh.Secrets.DatabaseDumpFile != archive || len(fresh.Secrets.DatabaseDumpSHA256) != 64 {
		t.Fatalf("bootstrap no longer binds private archive: %v", err)
	}
	projected := LifecycleProjection(fresh)
	if fresh.Secrets.DatabaseDumpFile != archive || fresh.SourceValues["DATABASE_DUMP"] != archive {
		t.Fatal("projection modified bootstrap plan")
	}
	if err = ValidatePlan(projected); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(archive); err != nil {
		t.Fatal(err)
	}
	if _, err = LoadConfig(config); err == nil {
		t.Fatal("bootstrap ignored missing archive")
	}
	lifecycle, err := LoadLifecycleConfig(config)
	if err != nil || ValidatePlan(lifecycle) != nil || lifecycle.Secrets.DatabaseDumpSHA256 != "" {
		t.Fatalf("lifecycle opened removed archive: %v", err)
	}
	lifecycle.Secrets.DatabaseDumpFile = archive
	if ValidatePlan(lifecycle) == nil {
		t.Fatal("lifecycle accepted a bootstrap archive reference")
	}
}
