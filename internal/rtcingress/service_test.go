package rtcingress

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/rtc"
	"github.com/NikitaDmitryuk/ultra/internal/rtcsupervisor"
	"github.com/NikitaDmitryuk/ultra/internal/subscriptionkey"
)

func TestServiceLifecycle(t *testing.T) {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("dedicated DATABASE_URL required")
	}
	ctx := context.Background()
	d, e := db.Open(ctx, dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer d.Close()
	users := db.NewUserRepo(d)
	a, e := users.Add(ctx, "vless", "rtc-lifecycle")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = users.Purge(ctx, a.UUID) }()
	b, e := users.Add(ctx, "vless", "rtc-other")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = users.Purge(ctx, b.UUID) }()
	socket := filepath.Join(t.TempDir(), "control.sock")
	l, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var sessions []rtcsupervisor.Session
		_ = json.NewDecoder(r.Body).Decode(&sessions)
		out := []rtcsupervisor.Status{}
		for _, s := range sessions {
			now := time.Now()
			out = append(out, rtcsupervisor.Status{Generation: s.Generation, Running: true, Ready: true, Checked: &now})
		}
		_ = json.NewEncoder(w).Encode(out)
	})}
	go func() { _ = server.Serve(l) }()
	defer func() { _ = server.Close() }()
	key := &subscriptionkey.Ring{Active: "test", Keys: map[string]string{"test": base64.StdEncoding.EncodeToString(make([]byte, 32))}}
	c := &rtc.PrivateContent{MaxAccesses: 10, ProbeURL: "https://probe.example/bytes", RoomRules: []rtc.RoomRule{{Host: "meet.example", PathPattern: `^/j/([0-9]+)$`, Provider: "wbstream"}}}
	s := New(db.NewRTCRepo(d), key, c, nil, socket)
	if e = s.Initialize(ctx, 0, nil); e != nil {
		t.Fatal(e)
	}
	defer s.Gateway.Close()
	first, e := s.Put(ctx, a.UUID, "https://meet.example/j/123", false)
	if e != nil {
		t.Fatal(e)
	}
	again, e := s.Put(ctx, a.UUID, "https://meet.example/j/123", false)
	if e != nil || first.Generation != again.Generation {
		t.Fatal("not idempotent", e)
	}
	profile, e := s.Profile(ctx, a.UUID)
	if e != nil || !strings.Contains(profile, "@123#") {
		t.Fatal("profile unavailable", e)
	}
	if _, e = s.Put(ctx, b.UUID, "https://meet.example/j/123", false); e == nil {
		t.Fatal("duplicate room accepted")
	}
	if _, e = s.Profile(ctx, b.UUID); e == nil {
		t.Fatal("cross owner profile returned")
	}
	stored, e := s.Repo.Get(ctx, a.UUID)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(stored.Cipher), "123") {
		t.Fatal("plaintext config stored")
	}
	if _, e = d.Pool.Exec(ctx, `UPDATE rtc_access SET updated_at=now()-interval '2 minutes' WHERE user_uuid=$1`, a.UUID); e != nil {
		t.Fatal(e)
	}
	replacement, e := s.Put(ctx, a.UUID, "https://meet.example/j/456", false)
	if e != nil || replacement.Generation == first.Generation {
		t.Fatal("generation not replaced", e)
	}
	profile, e = s.Profile(ctx, a.UUID)
	if e != nil || strings.Contains(profile, "@123#") {
		t.Fatal("old room exposed", e)
	}
	if e = users.Remove(ctx, a.UUID); e != nil {
		t.Fatal(e)
	}
	if e = s.Reconcile(ctx); e != nil {
		t.Fatal(e)
	}
	revoked, e := s.Repo.Get(ctx, a.UUID)
	if e != nil || revoked.Enabled {
		t.Fatal("disabled owner retained capacity", e)
	}
	if e = s.Delete(ctx, a.UUID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Profile(ctx, a.UUID); e == nil {
		t.Fatal("deleted access exported")
	}
}
