package cloud

import (
	"errors"
	"reflect"
	"testing"
)

type diagnosticFixture struct{}

func (diagnosticFixture) Error() string { return "verification failed" }
func (diagnosticFixture) CloudDiagnostics() map[string]any {
	return map[string]any{"reachable": true, "internet_ok": false}
}

func TestCloudDiagnosticsPreservesOnlyExplicitTypedDiagnostics(t *testing.T) {
	want := map[string]any{"reachable": true, "internet_ok": false}
	if got := cloudDiagnostics(errors.Join(errors.New("wrapped"), diagnosticFixture{})); !reflect.DeepEqual(got, want) {
		t.Fatalf("diagnostics = %#v, want %#v", got, want)
	}
	if got := cloudDiagnostics(errors.New("unstructured private error")); got != nil {
		t.Fatalf("untyped error diagnostics = %#v, want nil", got)
	}
}
