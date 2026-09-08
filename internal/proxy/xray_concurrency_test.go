//go:build xray_race_diagnostics

package proxy

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/transport/internet/splithttp"
)

type countedReader struct {
	io.Reader
	closes atomic.Int32
}

func (r *countedReader) Close() error { r.closes.Add(1); return nil }

func TestXHTTPReaderConcurrentPublicationAndClose(t *testing.T) {
	for i := 0; i < 100; i++ {
		w := &splithttp.WaitReadCloser{Wait: make(chan struct{})}
		body := &countedReader{Reader: bytes.NewReader([]byte("payload"))}
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); w.Set(body) }()
		go func() { defer wg.Done(); _, _ = io.ReadAll(w) }()
		go func() { defer wg.Done(); _ = w.Close() }()
		wg.Wait()
		_ = w.Close()
		if body.closes.Load() != 1 {
			t.Fatalf("body closed %d times", body.closes.Load())
		}
	}
}
