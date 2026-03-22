package adminapi

import (
	"net"
	"net/http"
	"sync"

	"golang.org/x/time/rate"
)

type visitorLimiter struct {
	mu      sync.Mutex
	byIP    map[string]*rate.Limiter
	limit   rate.Limit
	burst   int
	maxKeys int
}

func newVisitorLimiter(rps float64, burst int, maxKeys int) *visitorLimiter {
	return &visitorLimiter{
		byIP:    make(map[string]*rate.Limiter),
		limit:   rate.Limit(rps),
		burst:   burst,
		maxKeys: maxKeys,
	}
}

func (v *visitorLimiter) allow(ip string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.byIP) >= v.maxKeys && v.byIP[ip] == nil {
		return false
	}
	lim, ok := v.byIP[ip]
	if !ok {
		lim = rate.NewLimiter(v.limit, v.burst)
		v.byIP[ip] = lim
	}
	return lim.Allow()
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
