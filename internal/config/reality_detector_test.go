package config

import (
	"bytes"
	"errors"
	"io"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/reality"
)

type detectorFixtureConn struct {
	net.Conn
	data io.Reader
}

func (c detectorFixtureConn) Read(b []byte) (int, error)      { return c.data.Read(b) }
func (c detectorFixtureConn) SetReadDeadline(time.Time) error { return nil }

func TestRealityDetectorIncompleteRecord(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want []int
	}{
		{"truncated", []byte{23, 3, 3, 1, 0}, nil},
		{"complete_then_truncated", []byte{23, 3, 3, 0, 1, 42, 23, 3, 3, 1, 0}, []int{6}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := t.Name()
			defer reality.GlobalPostHandshakeRecordsLens.Delete(key)
			c := reality.PostHandshakeRecordDetectConn{Conn: detectorFixtureConn{data: bytes.NewReader(tc.data)}, Key: key, CcsSent: true}
			if _, err := c.Read(make([]byte, 512)); !errors.Is(err, io.EOF) {
				t.Fatalf("Read: %v", err)
			}
			got, _ := reality.GlobalPostHandshakeRecordsLens.Load(key)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("record lengths = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRealityDetectorClosesFailedProbes(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	var closed atomic.Int32
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 4096)
				if _, err := c.Read(buf); err != nil {
					return
				}
				// An invalid TLS response makes both probe handshakes fail.
				if _, err := c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n")); err != nil {
					return
				}
				for {
					if _, err := c.Read(buf); err != nil {
						if errors.Is(err, io.EOF) {
							closed.Add(1)
						}
						return
					}
				}
			}()
		}
	}()
	config := &reality.Config{Type: "tcp", Dest: l.Addr().String(), ServerNames: map[string]bool{"example.com": true}}
	reality.DetectPostHandshakeRecordsLens(config)
	deadline := time.Now().Add(4 * time.Second)
	for closed.Load() != 6 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := closed.Load(); got != 6 {
		t.Fatalf("closed probes = %d, want 6", got)
	}
}
