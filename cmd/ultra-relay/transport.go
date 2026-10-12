package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/xtls/xray-core/core"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
)

func runTransport(ctx context.Context, path string, check bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32768 {
		return fmt.Errorf("invalid transport spec file")
	}
	var spec config.ExperimentalTransportSpec
	d := json.NewDecoder(io.LimitReader(f, 32769))
	d.DisallowUnknownFields()
	if err = d.Decode(&spec); err != nil {
		return fmt.Errorf("invalid transport spec")
	}
	if err = d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("invalid transport spec suffix")
	}
	data, err := config.BuildExperimentalGateway(&spec)
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(spec.Profile.Endpoint.CertificateFile, spec.Profile.Endpoint.KeyFile)
	if err != nil {
		return fmt.Errorf("transport certificate unavailable")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("invalid transport certificate")
	}
	if err = leaf.VerifyHostname(spec.Profile.Endpoint.ServerName); err != nil {
		return fmt.Errorf("transport certificate name mismatch")
	}
	if time.Now().Before(leaf.NotBefore) || !time.Now().Before(leaf.NotAfter) {
		return fmt.Errorf("transport certificate not valid now")
	}
	if _, err := core.LoadConfig("json", bytes.NewReader(data)); err != nil {
		return fmt.Errorf("invalid experimental Xray configuration")
	}
	if check {
		return nil
	}
	var runner proxy.Runner
	if err = runner.StartJSON(data); err != nil {
		return err
	}
	defer func() { _ = runner.Close() }()
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", spec.Profile.StatusPort))
	if err != nil {
		return err
	}
	srv := &http.Server{ReadHeaderTimeout: 3 * time.Second}
	srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/ready" {
			http.NotFound(w, r)
			return
		}
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", spec.BackendPort), time.Second)
		ready := err == nil
		if conn != nil {
			_ = conn.Close()
		}
		w.Header().Set("Content-Type", "application/json")
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"ready": ready, "reload": runner.Status(), "certificate_not_after": leaf.NotAfter, "checked_at": time.Now().UTC()})
	})
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	select {
	case <-ctx.Done():
		_ = srv.Close()
		return nil
	case err := <-done:
		return err
	}
}
