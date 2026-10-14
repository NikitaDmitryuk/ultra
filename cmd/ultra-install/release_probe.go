package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// This command tests application evidence; it never installs files or changes services.
func runReleaseProbeCommand(args []string) {
	fs := flag.NewFlagSet("release-probe", flag.ExitOnError)
	spec := fs.String("spec", "/etc/ultra-relay/spec.json", "managed specification")
	environment := fs.String("environment", "/etc/ultra-relay/environment", "private managed environment")
	exit := fs.String("exit-id", "", "require fresh tunnel payload evidence for this exit")
	since := fs.Int64("since", 0, "minimum probe timestamp in Unix seconds")
	sinceNanos := fs.Int64("since-nanos", 0, "minimum probe timestamp in Unix nanoseconds")
	_ = fs.Parse(args)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	minimum := time.Unix(*since, 0)
	if *sinceNanos > 0 {
		minimum = time.Unix(0, *sinceNanos)
	}
	exitOnErr("release probe", releaseProbe(ctx, *spec, *environment, *exit, minimum))
}

func releaseProbe(ctx context.Context, specPath, environmentPath, exitID string, since time.Time) error {
	raw, err := os.ReadFile(specPath)
	if err != nil {
		return errors.New("probe_spec_unavailable")
	}
	var spec struct {
		AdminListen string `json:"admin_listen"`
	}
	if json.Unmarshal(raw, &spec) != nil {
		return errors.New("probe_spec_invalid")
	}
	if spec.AdminListen == "" {
		spec.AdminListen = "127.0.0.1:8443"
	}
	host, _, err := net.SplitHostPort(spec.AdminListen)
	if err != nil || host != "127.0.0.1" {
		return errors.New("probe_endpoint_not_loopback")
	}
	environment, err := os.ReadFile(environmentPath)
	if err != nil {
		return errors.New("probe_credentials_unavailable")
	}
	token := ""
	for _, line := range strings.Split(string(environment), "\n") {
		key, value, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(key) == "ULTRA_RELAY_ADMIN_TOKEN" {
			token = strings.Trim(strings.TrimSpace(value), "\"'")
		}
	}
	if token == "" {
		return errors.New("probe_credentials_unavailable")
	}
	// Intentionally bypass inherited HTTP(S)_PROXY and NO_PROXY.
	client := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	endpoint := "/v1/hardening"
	if exitID != "" {
		endpoint = "/v1/health"
	}
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+spec.AdminListen+endpoint, nil)
		if err != nil {
			return errors.New("probe_endpoint_invalid")
		}
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err == nil {
			body, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			_ = response.Body.Close()
			if readErr == nil && response.StatusCode == http.StatusOK && releaseEvidenceReady(body, exitID, since) {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("probe_payload_not_ready")
		case <-time.After(time.Second):
		}
	}
}

func releaseEvidenceReady(body []byte, exitID string, since time.Time) bool {
	if exitID == "" {
		var result struct {
			Reload struct {
				Count uint64 `json:"count"`
				Error string `json:"error"`
			} `json:"reload"`
		}
		return json.Unmarshal(body, &result) == nil && result.Reload.Count > 0 && result.Reload.Error == ""
	}
	var result struct {
		Exits []struct {
			ID         string    `json:"id"`
			InternetOK bool      `json:"internet_ok"`
			Eligible   bool      `json:"eligible"`
			CheckedAt  time.Time `json:"checked_at"`
		} `json:"exits"`
	}
	if json.Unmarshal(body, &result) != nil {
		return false
	}
	for _, exit := range result.Exits {
		if exit.ID == exitID && exit.InternetOK && exit.Eligible && !exit.CheckedAt.Before(since) {
			return true
		}
	}
	return false
}
