package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
)

func TestReplacementPingIsolatedXrayCoverage(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "example.com"},
		DNSNames:     []string{"example.com"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	d := t.TempDir()
	cert, keyfile := filepath.Join(d, "cert.pem"), filepath.Join(d, "key.pem")
	if err = os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyfile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	for _, transport := range []config.TunnelTransport{config.TunnelTransportSplitHTTP, config.TunnelTransportGRPC} {
		t.Run(string(transport), func(t *testing.T) {
			var hits atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != config.ExitPingPath {
					t.Error("wrong path")
				}
				hits.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer target.Close()
			l, e := net.Listen("tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			port := l.Addr().(*net.TCPAddr).Port
			_ = l.Close()
			spec := &config.Spec{
				Role:               config.RoleBridge,
				ListenAddress:      "127.0.0.1",
				PublicHost:         "127.0.0.1",
				VLESSPort:          port,
				DevMode:            true,
				ExitPing:           true,
				SplitRouting:       config.BoolPtr(true),
				RoutingMode:        config.RoutingModeRUDirect,
				GeoipDirectTags:    []string{},
				RuDirectTLDRegex:   config.BoolPtr(false),
				TunnelTransport:    transport,
				TunnelTLSProvision: config.TunnelTLSSelfSigned,
				SplithttpPath:      "/fixture",
				SplithttpHost:      "example.com",
				SplitHTTPTLS:       config.SplitHTTPTLSSpec{ServerName: "example.com"},
			}
			pin := sha256.Sum256(der)
			node := replacementPingRoute{
				ID:         "a6844f19-48ce-445a-bfda-3e8bfa108c18",
				Address:    "127.0.0.1",
				Port:       port,
				TunnelUUID: "de9cb0f8-6a24-4e4c-9b9c-a3bc75edc3ac",
				Pin:        hex.EncodeToString(pin[:]),
			}
			exit := *spec
			exit.Role = config.RoleExit
			exit.Exit = config.ExitTunnelSpec{TunnelUUID: node.TunnelUUID}
			exit.ExitCertPaths = config.CertPaths{CertFile: cert, KeyFile: keyfile}
			strategy, e := mimic.New("apijson")
			if e != nil {
				t.Fatal(e)
			}
			data, e := config.BuildExitXRayJSONWithPingPort(&exit, strategy, "none", target.Listener.Addr().(*net.TCPAddr).Port)
			if e != nil {
				t.Fatal(e)
			}
			var relay proxy.Runner
			if e = relay.StartJSON(data); e != nil {
				t.Fatal(e)
			}
			defer func() { _ = relay.Close() }()
			spec.MimicPreset = "apijson"
			if e = probeReplacementPing(context.Background(), spec, node); e != nil {
				t.Fatal(e)
			}
			if hits.Load() != 2 {
				t.Fatalf("selected exit received %d requests", hits.Load())
			}
			wrong := node
			wrong.TunnelUUID = "de9cb0f8-6a24-4e4c-9b9c-a3bc75edc3ad"
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if e = probeReplacementPing(ctx, spec, wrong); e == nil {
				t.Fatal("wrong exit identity passed coverage")
			}
			if hits.Load() != 2 {
				t.Fatal("wrong identity reached responder")
			}
		})
	}
}
