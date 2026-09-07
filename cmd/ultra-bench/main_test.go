package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestMeasurementDetectsTruncation(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "65536")
		_, _ = w.Write([]byte(strings.Repeat("x", 16384)))
	}))
	defer server.Close()
	var total atomic.Int64
	s := measure(context.Background(), server.Client(), server.URL, &total)
	if s.Error == "" || s.Bytes != 16384 || total.Load() != 16384 {
		t.Fatal(s)
	}
	if percentile(nil, .95) != nil || percentile([]int64{5, 1, 4, 2, 3}, .5) != int64(3) {
		t.Fatal("bad percentiles")
	}
}
