package rtc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T) Binding {
	t.Helper()
	root := t.TempDir()
	b := Binding{ID: "phone-wb", UserUUID: "2784871e-d8a9-4e1f-b831-3d86aa8653ee", Enabled: true, Provider: "wbstream", RoomID: "room-123", Transport: "vp8channel", ListenPort: 12001, KeyFile: filepath.Join(root, "key"), PasswordFile: filepath.Join(root, "pass"), BootstrapDNS: "77.88.8.8:53"}
	for _, p := range []string{b.KeyFile, b.PasswordFile} {
		if err := os.WriteFile(p, []byte(strings.Repeat("a", 64)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return b
}
func TestSubscriptionIsolationAndPrivateFiles(t *testing.T) {
	b := fixture(t)
	body, e := Subscription([]Binding{b}, b.UserUUID)
	if e != nil || !strings.Contains(body, "olcrtc://wbstream?") {
		t.Fatal(e)
	}
	if strings.Contains(body, b.PasswordFile) || strings.Contains(body, b.UserUUID) || strings.Contains(body, "##ip:") {
		t.Fatal("internal data in profile")
	}
	if _, e = Subscription([]Binding{b}, "other"); e == nil {
		t.Fatal("cross-user export")
	}
	b.Enabled = false
	if _, e = Subscription([]Binding{b}, b.UserUUID); e == nil {
		t.Fatal("disabled export")
	}
	b.Enabled = true
	if e = os.Chmod(b.KeyFile, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = Subscription([]Binding{b}, b.UserUUID); e == nil {
		t.Fatal("world-readable secret accepted")
	}
}
func TestValidationAndOwnerTag(t *testing.T) {
	b := fixture(t)
	if UserFromTag(b.Tag()) != b.UserUUID {
		t.Fatal("owner mapping")
	}
	for _, tag := range []string{"rtc-", "socks-" + b.UserUUID, b.Tag() + "\n"} {
		if UserFromTag(tag) != "" {
			t.Fatal("invalid tag accepted")
		}
	}
	if e := Validate([]Binding{b, b}); e == nil {
		t.Fatal("duplicate accepted")
	}
	for _, mutate := range []func(*Binding){func(b *Binding) { b.RoomID += "\n#evil" }, func(b *Binding) { b.Provider = "jitsi" }, func(b *Binding) { b.KeyFile = b.PasswordFile }, func(b *Binding) { b.BootstrapDNS = "dns.example:53" }, func(b *Binding) { b.ListenPort = 80 }} {
		c := b
		mutate(&c)
		if e := Validate([]Binding{c}); e == nil {
			t.Fatal("bad binding accepted")
		}
	}
}
