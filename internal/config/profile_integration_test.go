package config

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/auth"
	"github.com/NikitaDmitryuk/ultra/internal/mimic"
	"github.com/NikitaDmitryuk/ultra/internal/proxy"
	"github.com/NikitaDmitryuk/ultra/internal/realitykey"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	p := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return p
}
func testCertificate(t *testing.T) (string, string) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "example.com"}, DNSNames: []string{"example.com"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := x509.MarshalECPrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if e = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: raw}), 0600); e != nil {
		t.Fatal(e)
	}
	return certFile, keyFile
}
func TestPublishedProfilesLocalTransfer(t *testing.T) {
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 65536))) }))
	defer destination.Close()
	camouflage := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	camouflage.EnableHTTP2 = true
	camouflage.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	camouflage.StartTLS()
	defer camouflage.Close()
	keys, e := realitykey.Generate()
	if e != nil {
		t.Fatal(e)
	}
	certFile, keyFile := testCertificate(t)
	s := bridgeSpecForAntiCensorTest()
	s.DevMode = false
	s.SplitRouting = BoolPtr(false)
	s.PublicHost = "127.0.0.1"
	s.ListenAddress = "127.0.0.1"
	s.VLESSPort = freePort(t)
	s.Reality = RealitySpec{PrivateKey: keys.PrivateKey, PublicKey: keys.PublicKey, Dest: camouflage.Listener.Addr().String(), ServerNames: []string{"example.com"}}
	s.AntiCensor = &AntiCensorSpec{PublicXHTTPPort: freePort(t)}
	s.PublicXHTTPTLS = &PublicXHTTPTLSSpec{Port: freePort(t), ServerName: "example.com", CertificateFile: certFile, KeyFile: keyFile, Path: "/test", Mode: "stream-up"}
	user := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", Name: "test", IsActive: true, Kind: "vless"}
	strat, _ := mimic.New("steamlike")
	data, e := BuildBridgeXRayJSON(s, []auth.User{user}, nil, "", strat, "error")
	if e != nil {
		t.Fatal(e)
	}
	if _, err := core.LoadConfig("json", bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	var server map[string]any
	if e = json.Unmarshal(data, &server); e != nil {
		t.Fatal(e)
	}
	// Exercise the public transport independently of the separately tested exit selector.
	server["inbounds"] = server["inbounds"].([]any)[:3]
	server["outbounds"] = []any{map[string]any{"protocol": "freedom"}}
	delete(server, "routing")
	delete(server, "dns")
	data, _ = json.Marshal(server)
	var relay proxy.Runner
	if e = relay.StartJSON(data); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = relay.Close() }()
	for _, port := range []int{s.VLESSPort, s.AntiCensor.PublicXHTTPPort, s.PublicXHTTPTLS.Port} {
		deadline := time.Now().Add(time.Second)
		for {
			c, e := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 50*time.Millisecond)
			if e == nil {
				_ = c.Close()
				break
			}
			if time.Now().After(deadline) {
				t.Fatal(e)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	profiles, e := BuildClientProfiles(s, user)
	if e != nil {
		t.Fatal(e)
	}
	if len(profiles) != 3 {
		t.Fatal(len(profiles))
	}
	for _, profile := range profiles {
		t.Run(profile.ID, func(t *testing.T) {
			outbound := profile.XRayOutboundJSON
			if profile.ID == "fallback_xhttp_tls" {
				settings := outbound["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)
				settings["certificates"] = []any{map[string]any{"certificateFile": certFile, "usage": "verify"}}
			}
			roundTrip := func(outbound map[string]any) error {
				clientJSON, _ := json.Marshal(map[string]any{"log": map[string]any{"loglevel": "error"}, "outbounds": []any{outbound}})
				var client proxy.Runner
				if e := client.StartJSON(clientJSON); e != nil {
					return e
				}
				defer func() { _ = client.Close() }()
				tr := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					d, e := xnet.ParseDestination(network + ":" + addr)
					if e != nil {
						return nil, e
					}
					return core.Dial(ctx, client.Instance(), d)
				}}
				defer tr.CloseIdleConnections()
				hc := &http.Client{Transport: tr, Timeout: 3 * time.Second}
				resp, e := hc.Get(destination.URL)
				if e != nil {
					return e
				}
				defer func() { _ = resp.Body.Close() }()
				body, e := io.ReadAll(resp.Body)
				if e != nil {
					return e
				}
				if len(body) != 65536 {
					t.Fatalf("short body: %d", len(body))
				}
				return nil
			}
			if e := roundTrip(outbound); e != nil {
				t.Fatal(e)
			}
			if profile.ID == "fallback_xhttp_tls" {
				outbound["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)["serverName"] = "wrong.example.com"
				if e := roundTrip(outbound); e == nil {
					t.Fatal("wrong certificate name accepted")
				}
			}
		})
	}
}
func TestProfilesPreserveLegacyAndExplicitEntries(t *testing.T) {
	s := bridgeSpecForAntiCensorTest()
	s.DevMode = false
	u := auth.User{UUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", Name: "old"}
	legacy, e := BuildClientExport(s, u)
	if e != nil {
		t.Fatal(e)
	}
	profiles, e := BuildClientProfiles(s, u)
	if e != nil || len(profiles) != 1 {
		t.Fatal(profiles, e)
	}
	s.PublicEntries = []PublicEntry{{ID: "backup", Host: "backup.example", TCPPort: 8443}}
	profiles, e = BuildClientProfiles(s, u)
	if e != nil {
		t.Fatal(e)
	}
	if profiles[0].VLESSURI != legacy.VLESSURI {
		t.Fatal("changed issued primary")
	}
	if len(profiles) != 2 || profiles[1].EntryID != "backup" || !strings.Contains(profiles[1].VLESSURI, ":"+strconv.Itoa(8443)) {
		t.Fatal(profiles)
	}
}
