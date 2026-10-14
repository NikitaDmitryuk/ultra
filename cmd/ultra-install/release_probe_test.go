package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReleaseProbeUsesAuthenticatedLoopbackWithoutProxy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-token" || r.URL.Path != "/v1/hardening" {
			t.Error("probe authentication or endpoint differs from contract")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"reload":{"count":1,"error":""}}`))
	}))
	defer server.Close()
	directory := t.TempDir()
	spec, environment := filepath.Join(directory, "spec.json"), filepath.Join(directory, "environment")
	if err := os.WriteFile(spec, []byte(`{"admin_listen":"`+strings.TrimPrefix(server.URL, "http://")+`"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(environment, []byte("ULTRA_RELAY_ADMIN_TOKEN=fixture-token\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:9")
	t.Setenv("NO_PROXY", "")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := releaseProbe(ctx, spec, environment, "", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(spec, []byte(`{"admin_listen":"192.0.2.1:8443"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := releaseProbe(ctx, spec, environment, "", time.Time{}); err == nil || err.Error() != "probe_endpoint_not_loopback" {
		t.Fatal("non-loopback token destination accepted")
	}
}

func TestReleaseEvidenceRequiresFreshEligiblePayload(t *testing.T) {
	since := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		body string
		want bool
	}{
		{`{"exits":[{"id":"a","internet_ok":true,"eligible":true,"checked_at":"2026-01-01T00:00:01Z"}]}`, true},
		{`{"exits":[{"id":"a","internet_ok":true,"eligible":true,"checked_at":"2025-12-31T23:59:59Z"}]}`, false},
		{`{"exits":[{"id":"b","internet_ok":true,"eligible":true,"checked_at":"2026-01-01T00:00:01Z"}]}`, false},
		{`{"exits":[{"id":"a","internet_ok":true,"eligible":false,"checked_at":"2026-01-01T00:00:01Z"}]}`, false},
		{`{"exits":[{"id":"a","internet_ok":false,"eligible":true,"checked_at":"2026-01-01T00:00:01Z"}]}`, false},
	} {
		if got := releaseEvidenceReady([]byte(tc.body), "a", since); got != tc.want {
			t.Fatalf("got %v want %v: %s", got, tc.want, tc.body)
		}
	}
	for _, tc := range []struct {
		body string
		want bool
	}{
		{`{"reload":{"count":1,"error":""}}`, true},
		{`{"reload":{"count":0,"error":""}}`, false},
		{`{"reload":{"count":1,"error":"failure"}}`, false},
	} {
		if got := releaseEvidenceReady([]byte(tc.body), "", since); got != tc.want {
			t.Fatalf("reload got %v want %v", got, tc.want)
		}
	}
}
