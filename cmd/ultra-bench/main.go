// Command ultra-bench measures HTTP payload delivery over a direct or explicit proxy route.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type sample struct {
	Target    string `json:"target"`
	Run       int    `json:"run"`
	Stream    int    `json:"stream"`
	Status    int    `json:"status"`
	Bytes     int64  `json:"bytes"`
	DNSMS     int64  `json:"dns_ms"`
	ConnectMS int64  `json:"connect_ms"`
	TLSMS     int64  `json:"tls_ms"`
	FirstMS   int64  `json:"first_byte_ms"`
	TotalMS   int64  `json:"total_ms"`
	Error     string `json:"error,omitempty"`
}

func measure(ctx context.Context, c *http.Client, target string, total *atomic.Int64) sample {
	parsed, _ := url.Parse(target)
	s := sample{Target: parsed.Hostname() + parsed.Path}
	start := time.Now()
	var dns, connect, tlsDone, first atomic.Int64
	trace := &httptrace.ClientTrace{TLSHandshakeDone: func(tls.ConnectionState, error) { tlsDone.Store(time.Since(start).Milliseconds()) }, DNSDone: func(httptrace.DNSDoneInfo) { dns.Store(time.Since(start).Milliseconds()) }, ConnectDone: func(_, _ string, _ error) { connect.Store(time.Since(start).Milliseconds()) }, GotFirstResponseByte: func() { first.Store(time.Since(start).Milliseconds()) }}
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), "GET", target, nil)
	if err == nil {
		req.Header.Set("Accept-Encoding", "identity")
		resp, e := c.Do(req)
		err = e
		if err == nil {
			s.Status = resp.StatusCode
			buf := make([]byte, 32*1024)
			for {
				n, e := resp.Body.Read(buf)
				s.Bytes += int64(n)
				total.Add(int64(n))
				if e != nil {
					if e != io.EOF {
						err = e
					}
					break
				}
			}
			_ = resp.Body.Close()
			if s.Status < 200 || s.Status >= 300 {
				s.Error = "http_status"
			}
		}
	}
	if err != nil {
		s.Error = "transport_error"
		if ctx.Err() != nil {
			s.Error = "deadline_or_cancel"
		}
	}
	s.DNSMS, s.ConnectMS, s.TLSMS, s.FirstMS = dns.Load(), connect.Load(), tlsDone.Load(), first.Load()
	s.TotalMS = time.Since(start).Milliseconds()
	return s
}
func run() error {
	targets := flag.String("urls", "https://httpbingo.org/bytes/65536,https://speed.cloudflare.com/__down?bytes=65536,https://gemini.google.com/", "comma-separated HTTPS GET targets")
	proxyURL := flag.String("proxy", "", "explicit http:// or socks5h:// proxy, empty means direct")
	repeats := flag.Int("repeat", 5, "repetitions")
	streams := flag.Int("streams", 1, "parallel streams (1 or 4)")
	duration := flag.Duration("duration", 0, "repeat for at least this duration, e.g. 5m")
	flag.Parse()
	if *repeats < 1 || (*streams != 1 && *streams != 4) || *duration < 0 {
		return fmt.Errorf("invalid repetition, streams or duration")
	}
	urls := strings.Split(*targets, ",")
	for _, t := range urls {
		u, err := url.Parse(t)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return fmt.Errorf("targets must be HTTPS URLs without credentials")
		}
	}
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 5 * time.Second, DisableKeepAlives: true}
	if *proxyURL != "" {
		u, err := url.Parse(*proxyURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "socks5" && u.Scheme != "socks5h") {
			return fmt.Errorf("invalid proxy")
		}
		tr.Proxy = http.ProxyURL(u)
	}
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer tr.CloseIdleConnections()
	var mu sync.Mutex
	enc := json.NewEncoder(os.Stdout)
	emit := func(v any) { mu.Lock(); defer mu.Unlock(); _ = enc.Encode(v) }
	var total atomic.Int64
	done := make(chan struct{})
	var sampler sync.WaitGroup
	sampler.Add(1)
	go func() {
		defer sampler.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		prev := int64(0)
		for {
			select {
			case <-done:
				return
			case now := <-ticker.C:
				next := total.Load()
				emit(map[string]any{"at": now.UTC(), "bytes_per_second": next - prev})
				prev = next
			}
		}
	}()
	defer func() { close(done); sampler.Wait() }()
	end := time.Now().Add(*duration)
	failures := atomic.Int64{}
	var samplesMu sync.Mutex
	samples := map[string][]sample{}
	for run := 1; run <= *repeats || (*duration > 0 && time.Now().Before(end)); run++ {
		for _, target := range urls {
			var wg sync.WaitGroup
			for stream := 1; stream <= *streams; stream++ {
				wg.Add(1)
				go func(stream int) {
					defer wg.Done()
					ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
					defer cancel()
					s := measure(ctx, client, target, &total)
					s.Run = run
					s.Stream = stream
					emit(s)
					samplesMu.Lock()
					samples[s.Target] = append(samples[s.Target], s)
					samplesMu.Unlock()
					if s.Error != "" {
						failures.Add(1)
					}
				}(stream)
			}
			wg.Wait()
		}
	}
	for target, entries := range samples {
		first, connect := []int64{}, []int64{}
		errors := 0
		for _, s := range entries {
			if s.Error != "" {
				errors++
				continue
			}
			first = append(first, s.FirstMS)
			connect = append(connect, s.ConnectMS)
		}
		emit(map[string]any{"summary": target, "requests": len(entries), "error_fraction": float64(errors) / float64(len(entries)), "ttfb_median_ms": percentile(first, .5), "ttfb_p95_ms": percentile(first, .95), "connect_median_ms": percentile(connect, .5), "connect_p95_ms": percentile(connect, .95)})
	}
	if failures.Load() > 0 {
		return fmt.Errorf("%d unsuccessful transfers", failures.Load())
	}
	return nil
}
func percentile(values []int64, p float64) any {
	if len(values) == 0 {
		return nil
	}
	slices.Sort(values)
	return values[int(math.Ceil(float64(len(values))*p))-1]
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
