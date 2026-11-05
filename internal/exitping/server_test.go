package exitping

import (
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestResponderContractAndShutdown(t *testing.T) {
	s, err := Start()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(s.Port()))
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", Path, 204}, {"HEAD", Path, 204}, {"POST", Path, 405}, {"GET", "/", 404}, {"GET", Path + "/", 404},
	} {
		req, err := http.NewRequest(tc.method, "http://"+addr+tc.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil || resp.StatusCode != tc.status || len(body) != 0 {
			t.Fatalf("%s %s: status=%d body=%q err=%v", tc.method, tc.path, resp.StatusCode, body, err)
		}
		if resp.Header.Get("Cache-Control") != "no-store, no-cache, must-revalidate" {
			t.Fatal("response is cacheable")
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err == nil {
		_ = conn.Close()
		t.Fatal("responder listener survived shutdown")
	}
}
