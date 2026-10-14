package installplan

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDiagnosticConfigSharesParserAndRejectsSecretOrFramingInjection(t *testing.T) {
	source := filepath.Join(t.TempDir(), "config")
	write := func(data string) {
		t.Helper()
		if err := os.WriteFile(source, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("BRIDGE='192.0.2.1' # comment\nBOT_PUBLIC_URL='https://example.com/#section'\nHOME=/unexpected\n")
	values, err := DiagnosticConfig(source)
	if err != nil {
		t.Fatal(err)
	}
	if values["BRIDGE"] != "192.0.2.1" || values["BOT_PUBLIC_URL"] != "https://example.com/#section" {
		t.Fatal("canonical parsing changed", values)
	}
	if _, ok := values["HOME"]; ok {
		t.Fatal("arbitrary shell variable exposed")
	}
	write("BRIDGE=x\x00HOME\x00/unexpected\n")
	if _, err := DiagnosticConfig(source); err == nil {
		t.Fatal("NUL framing injection accepted")
	}
	write("TELEGRAM_BOT_TOKEN=fixture\n")
	if _, err := DiagnosticConfig(source); err == nil {
		t.Fatal("secret in configuration accepted")
	}
}
