package config

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/proxy"
)

func TestCertificateReplacementReloadsOfficialCore(t *testing.T) {
	cert, key := testCertificate(t)
	spec := &Spec{PublicXHTTPTLS: &PublicXHTTPTLSSpec{CertificateFile: cert, KeyFile: key, ServerName: "example.com", Path: "/test"}}
	stream := publicTLSStream(spec, true)
	certificate := stream["tlsSettings"].(map[string]any)["certificates"].([]any)[0].(map[string]any)
	if certificate["oneTimeLoading"] != true {
		t.Fatal("certificate ticker must be disabled")
	}
	data, err := json.Marshal(map[string]any{"inbounds": []any{map[string]any{"listen": "127.0.0.1", "port": 0, "protocol": "vless", "settings": map[string]any{"decryption": "none", "clients": []any{}}, "streamSettings": stream}}, "outbounds": []any{map[string]any{"protocol": "freedom"}}})
	if err != nil {
		t.Fatal(err)
	}
	var runner proxy.Runner
	if err := runner.StartJSON(data); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = runner.Close() }()
	before := runner.Status().Count
	if err := runner.Reload(data); err != nil {
		t.Fatal(err)
	}
	if runner.Status().Count != before {
		t.Fatal("unchanged certificate caused reload")
	}
	nextCert, nextKey := testCertificate(t)
	for target, source := range map[string]string{cert: nextCert, key: nextKey} {
		content, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := runner.ReloadReason(data, "certificate renewed"); err != nil {
		t.Fatal(err)
	}
	if runner.Status().Count != before+1 {
		t.Fatal("replacement certificate did not cause exactly one reload")
	}
}
