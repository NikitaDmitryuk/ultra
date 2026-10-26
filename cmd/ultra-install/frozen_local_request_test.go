package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/deployansible"
)

func TestFrozenLocalRequestPreservesCompleteBudgetBinding(t *testing.T) {
	inventory, variables := map[string]any{}, map[string]any{}
	for _, raw := range []string{`{"inventory":{},"variables":{}}`, `{"execution_timeout_seconds":7200,"inventory":{},"variables":{}}`} {
		expected, err := expectedFrozenLocalRequest([]byte(raw), inventory, variables)
		if err != nil || string(expected) != raw {
			t.Fatal(raw, string(expected), err)
		}
	}
	for _, raw := range []string{
		`{"execution_timeout_seconds":0,"inventory":{},"variables":{}}`,
		`{"execution_timeout_seconds":-1,"inventory":{},"variables":{}}`,
		`{"execution_timeout_seconds":1.5,"inventory":{},"variables":{}}`,
		`{"execution_timeout_seconds":"1","inventory":{},"variables":{}}`,
		`{"execution_timeout_seconds":9223371977,"inventory":{},"variables":{}}`,
		`{"execution_timeout_seconds":1,"execution_timeout_seconds":2,"inventory":{},"variables":{}}`,
		`{"execution_timeout_seconds":null,"inventory":{},"variables":{}}`,
		`{"inventory":{},"variables":{},"unrecognized":true}`,
		`{"inventory":{"changed":true},"variables":{}}`,
		`{"inventory":{},"variables":{"changed":true}}`,
	} {
		expected, err := expectedFrozenLocalRequest([]byte(raw), inventory, variables)
		if err == nil && bytes.Equal(expected, []byte(raw)) {
			t.Fatal("invalid or changed request accepted", raw)
		}
	}
}

func TestBootstrapComponentReceiptCustomTimeoutCannotEscapeHashOrCallerBudget(t *testing.T) {
	directory := t.TempDir()
	inventory, variables := map[string]any{}, map[string]any{}
	raw := []byte(`{"execution_timeout_seconds":7200,"inventory":{},"variables":{}}`)
	write := func(name string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(directory, "request.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	hash := digestSHA256(raw)
	identity := map[string]any{
		"schema_version": 1,
		"operation":      "bootstrap",
		"request_sha256": hash,
		"binary_sha256":  hash,
		"state":          "succeeded",
		"result":         map[string]any{"verified": true},
	}
	write("job.json", identity)
	write("receipt.json", identity)
	if err := verifyBootstrapComponentReceipt(directory, "bootstrap", inventory, variables); err != nil {
		t.Fatal(err)
	}
	ctx, err := deployansible.WithExecutionTimeout(context.Background(), 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyBootstrapComponentReceipt(directory, "bootstrap", inventory, variables, ctx); err != nil {
		t.Fatal(err)
	}
	if err = verifyBootstrapComponentReceipt(directory, "bootstrap", inventory, variables, context.Background()); err != nil {
		t.Fatal("omitted override did not preserve admitted budget", err)
	}
	changedContext, err := deployansible.WithExecutionTimeout(context.Background(), 20*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyBootstrapComponentReceipt(directory, "bootstrap", inventory, variables, changedContext); err == nil {
		t.Fatal("changed caller timeout accepted")
	}
	changed := bytes.Replace(raw, []byte("7200"), []byte("7201"), 1)
	if err = os.WriteFile(filepath.Join(directory, "request.json"), changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err = verifyBootstrapComponentReceipt(directory, "bootstrap", inventory, variables); err == nil {
		t.Fatal("timeout changed without receipt identity")
	}
}
