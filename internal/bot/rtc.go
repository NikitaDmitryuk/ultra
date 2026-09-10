package bot

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

func (b *Bot) rtcFeatures(r *http.Request) map[string]bool {
	features := map[string]bool{"rtc": false}
	_, _ = b.relayJSON(r.Context(), "GET", "/v1/features", nil, &features)
	return features
}
func (b *Bot) rtcRoutes(mux *http.ServeMux) {
	for _, pattern := range []string{"GET /api/self/rtc", "PUT /api/self/rtc", "DELETE /api/self/rtc", "GET /api/self/rtc/guide", "GET /api/self/rtc/profile", "GET /api/self/rtc/traffic", "POST /api/self/rtc/retry"} {
		mux.HandleFunc(pattern, b.selfRTC)
	}
	mux.HandleFunc("GET /api/rtc/traffic", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := b.mustAdmin(w, r); !ok {
			return
		}
		b.proxyRTC(w, r, "/v1/rtc/traffic", nil)
	})
}
func (b *Bot) selfRTC(w http.ResponseWriter, r *http.Request) {
	u, ok := b.selfAuth(w, r)
	if !ok {
		return
	}
	if u.ID <= 0 {
		memberHTTPError(w, 401)
		return
	}
	var input any
	if r.Method == "PUT" {
		var body struct {
			URL string `json:"url"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			memberHTTPError(w, 400)
			return
		}
		input = body
	}
	suffix := strings.TrimPrefix(r.URL.Path, "/api/self/rtc")
	b.proxyRTC(w, r, fmt.Sprintf("/v1/members/%d/rtc%s", u.ID, suffix), input)
}
func (b *Bot) proxyRTC(w http.ResponseWriter, r *http.Request, path string, input any) {
	w.Header().Set("Cache-Control", "no-store")
	var output json.RawMessage
	status, e := b.relayJSON(r.Context(), r.Method, path, input, &output)
	if e != nil {
		var detail relayCloudError
		if errors.As(e, &detail) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": detail.Code})
			return
		}
		memberHTTPError(w, status)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(output)
}
