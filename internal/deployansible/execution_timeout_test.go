package deployansible

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecutionTimeoutPolicy(t *testing.T) {
	for _, invalid := range []time.Duration{0, -time.Second, time.Millisecond, time.Duration(1<<63 - 1)} {
		if _, err := WithExecutionTimeout(context.Background(), invalid); err == nil {
			t.Fatal(invalid)
		}
	}
	ctx, err := WithExecutionTimeout(context.Background(), 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if executionTimeoutSeconds(ctx, "upgrade") != 7200 || executionTimeoutSeconds(ctx, "wait-upgrade-readiness") != 700 ||
		executionTimeoutSeconds(
			context.Background(),
			"upgrade",
		) != 3600 || executionTimeoutSeconds(context.Background(), "bootstrap") != 1200 {
		t.Fatal("timeout policy")
	}
}

func TestExecutionRuntimeLimitSurvivesObserverCrashWithoutRetiringFence(t *testing.T) {
	fence, _ := containmentCompletionFixture(t)
	resolver := executionFenceDirectory
	executionFenceDirectory = func(string) string { return "/var/lib/ultra-ansible" }
	t.Cleanup(func() { executionFenceDirectory = resolver })
	mockContainmentObservation(t, func(string) (map[string]string, error) {
		return map[string]string{
			"LoadState": "loaded", "Result": "timeout", "InvocationID": strings.Repeat("b", 32)}, nil
	})
	before, err := os.ReadFile(filepath.Join(fence.JobDirectory, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = observeExecutionRuntimeLimit(*fence); !errors.Is(err, errExecutionRuntimeLimit) {
		t.Fatal(err)
	}
	observeContainmentUnit = func(string) (map[string]string, error) { t.Fatal("durable timeout reobserved"); return nil, nil }
	if err = observeExecutionRuntimeLimit(*fence); !errors.Is(err, errExecutionRuntimeLimit) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(fence.JobDirectory, "receipt.json"))
	if string(before) != string(after) {
		t.Fatal("receipt overwritten")
	}
	executionFenceDirectory = resolver
	if err = ReconcileExecutionFence(*fence); !errors.Is(err, errExecutionRuntimeLimit) {
		t.Fatal(err)
	}
	if current, err := InspectExecutionFence(); err != nil || current == nil {
		t.Fatal(current, err)
	}
}

func TestPreparedExecutionTimeoutRejectsChangedRequest(t *testing.T) {
	directory := t.TempDir()
	if err := writeJSON(filepath.Join(directory, "request.json"), map[string]any{"execution_timeout_seconds": 0}); err != nil {
		t.Fatal(err)
	}
	if _, err := preparedExecutionTimeout(directory); err == nil {
		t.Fatal("zero timeout accepted")
	}
}

func TestLegacyUpgradeBudgetDoesNotInheritFreshDefault(t *testing.T) {
	directory := t.TempDir()
	if err := writeJSON(filepath.Join(directory, "request.json"), map[string]any{"inventory": map[string]any{}, "variables": map[string]any{}}); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(filepath.Join(directory, "job.json"), map[string]any{"operation": "upgrade"}); err != nil {
		t.Fatal(err)
	}
	if budget, err := preparedExecutionTimeout(directory); err != nil || budget != 20*time.Minute {
		t.Fatal(budget, err)
	}
	raw, err := LocalRequestBytes(context.Background(), "upgrade", filepath.Join(directory, "fresh"), map[string]any{}, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"execution_timeout_seconds":3600`) {
		t.Fatal(string(raw))
	}
}

func TestExecutionTimeoutRequestBudgetIsImmutableAndLegacyReplayPreservesBytes(t *testing.T) {
	directory := t.TempDir()
	inventory, variables := map[string]any{}, map[string]any{}
	legacy := []byte(`{"inventory":{},"variables":{}}`)
	if err := writePrivate(filepath.Join(directory, "request.json"), legacy); err != nil {
		t.Fatal(err)
	}
	raw, err := localExecutionRequest(context.Background(), "bootstrap", directory, inventory, variables)
	if err != nil || string(raw) != string(legacy) {
		t.Fatal(string(raw), err)
	}
	ctx, err := WithExecutionTimeout(context.Background(), 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = localExecutionRequest(ctx, "bootstrap", directory, inventory, variables)
	if err != nil || string(raw) == string(legacy) {
		t.Fatal("changed budget reused old bytes", err)
	}
	newDirectory := filepath.Join(directory, "new")
	if err = prepareLocalOperation(newDirectory, "bootstrap", raw, executionHash(raw), Export); err != nil {
		t.Fatal(err)
	}
	defaultOverride, err := WithExecutionTimeout(context.Background(), 20*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := localExecutionRequest(defaultOverride, "bootstrap", newDirectory, inventory, variables)
	if err != nil {
		t.Fatal(err)
	}
	if err = prepareLocalOperation(newDirectory, "bootstrap", changed, executionHash(changed), Export); err == nil {
		t.Fatal("changed immutable timeout accepted")
	}
}

func TestProductionContainmentNamespaceHasNoRequestOverride(t *testing.T) {
	t.Setenv("ULTRA_EXECUTION_ROOT", t.TempDir())
	for _, directory := range []string{"", t.TempDir(), "/var/lib/ultra-ansible", "/tmp/../tmp/untrusted"} {
		if got := productionExecutionFenceDirectory(directory); got != "/var/lib/ultra-ansible" {
			t.Fatalf("job path or environment changed production containment: %q", got)
		}
	}
}

func TestPinnedLegacySameOperationGenerationPreservesSourceWireBytes(t *testing.T) {
	source, receipt := retryFixture(t)
	jobRaw, err := os.ReadFile(filepath.Join(source, "job.json"))
	if err != nil {
		t.Fatal(err)
	}
	var job map[string]any
	if json.Unmarshal(jobRaw, &job) != nil {
		t.Fatal("fixture job")
	}
	job["operation"] = "bootstrap-postgres"
	jobRaw, _ = json.Marshal(job)
	if err = os.WriteFile(filepath.Join(source, "job.json"), jobRaw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = Export(filepath.Join(source, "bundle")); err != nil {
		t.Fatal(err)
	}
	legacy, err := os.ReadFile(filepath.Join(source, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(source, "next-generation")
	raw, err := pinnedLocalExecutionRequest(context.Background(), "bootstrap-postgres", target, source, map[string]any{}, map[string]any{})
	if err != nil || !bytes.Equal(raw, legacy) {
		t.Fatal(string(raw), err)
	}
	export, err := pinnedBootstrapExporter(source, target, "bootstrap-postgres", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = prepareLocalOperation(target, "bootstrap-postgres", raw, executionHash(raw), export); err != nil {
		t.Fatal(err)
	}
	copied, err := os.ReadFile(filepath.Join(target, "request.json"))
	if err != nil || !bytes.Equal(copied, legacy) {
		t.Fatal("legacy request rebound", err)
	}
	if _, err = os.Lstat(filepath.Join(target, "receipt.json")); !os.IsNotExist(err) {
		t.Fatal("source receipt fabricated at target", err)
	}
	unchanged, err := os.ReadFile(filepath.Join(source, "receipt.json"))
	if err != nil || !bytes.Equal(unchanged, receipt) {
		t.Fatal("source receipt changed", err)
	}
	for _, variables := range []map[string]any{{}, {"changed": true}} {
		ctx := context.Background()
		if len(variables) == 0 {
			ctx, err = WithExecutionTimeout(ctx, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
		}
		drift, err := pinnedLocalExecutionRequest(
			ctx,
			"bootstrap-postgres",
			filepath.Join(source, "changed"),
			source,
			map[string]any{},
			variables,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = pinnedBootstrapExporter(source, filepath.Join(source, "changed"), "bootstrap-postgres", drift); err == nil {
			t.Fatal("changed budget/inputs silently rebound")
		}
	}
}

func TestFrozenCustomBudgetContinuesWithoutOverrideAndRejectsChangedOverride(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "job")
	ctx, err := WithOperationExecutionTimeout(context.Background(), "upgrade", 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	request, err := localExecutionRequest(ctx, "upgrade", directory, map[string]any{}, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if err = prepareLocalOperation(directory, "upgrade", request, executionHash(request), Export); err != nil {
		t.Fatal(err)
	}
	continued, err := localExecutionRequest(context.Background(), "upgrade", directory, map[string]any{}, map[string]any{})
	if err != nil || !bytes.Equal(continued, request) {
		t.Fatal("custom budget lost on continuation", string(continued), err)
	}
	ctx, err = WithOperationExecutionTimeout(context.Background(), "upgrade", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := localExecutionRequest(ctx, "upgrade", directory, map[string]any{}, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if err = prepareLocalOperation(directory, "upgrade", changed, executionHash(changed), Export); err == nil {
		t.Fatal("explicit changed budget admitted")
	}
	for _, invalid := range []string{
		`{"execution_timeout_seconds":null,"inventory":{},"variables":{}}`,
		`{"execution_timeout_seconds":0,"inventory":{},"variables":{}}`,
		`{"execution_timeout_seconds":-1,"inventory":{},"variables":{}}`,
		`{"execution_timeout_seconds":1.5,"inventory":{},"variables":{}}`,
		`{"execution_timeout_seconds":9223372036854775807,"inventory":{},"variables":{}}`,
		`{"execution_timeout_seconds":1200,"execution_timeout_seconds":7200,"inventory":{},"variables":{}}`,
		`{"execution_timeout_seconds":7200,"inventory":{},"unknown":true,"variables":{}}`,
	} {
		if err = os.WriteFile(filepath.Join(directory, "request.json"), []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = localExecutionRequest(context.Background(), "upgrade", directory, map[string]any{}, map[string]any{}); err == nil {
			t.Fatalf("invalid frozen budget accepted: %s", invalid)
		}
	}
}
