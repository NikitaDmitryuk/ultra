package bot

import (
	"encoding/json"
	"errors"
	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"net/http"
	"net/url"
)

func (b *Bot) cloudRoutes(mux *http.ServeMux) {
	for _, route := range []string{"GET /api/cloud/account", "GET /api/cloud/quotas", "GET /api/cloud/operations/{id}/events", "GET /api/cloud/replicas", "GET /api/cloud/catalog", "GET /api/cloud/operations", "POST /api/cloud/offers", "POST /api/cloud/offers/{id}/confirm", "POST /api/cloud/operations/{id}/action"} {
		mux.HandleFunc(route, b.cloudProxy)
	}
}
func (b *Bot) cloudProxy(w http.ResponseWriter, r *http.Request) {
	actor, ok := b.mustAdmin(w, r)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	path := ""
	switch r.Pattern {
	case "GET /api/cloud/account":
		path = "/v1/cloud/account"
	case "GET /api/cloud/quotas":
		path = "/v1/cloud/quotas"
	case "GET /api/cloud/operations/{id}/events":
		path = "/v1/cloud/operations/" + url.PathEscape(r.PathValue("id")) + "/events"
	case "GET /api/cloud/replicas":
		path = "/v1/cloud/replicas"
	case "GET /api/cloud/catalog":
		path = "/v1/cloud/catalog"
	case "GET /api/cloud/operations":
		path = "/v1/cloud/operations"
	case "POST /api/cloud/offers":
		path = "/v1/cloud/offers"
	case "POST /api/cloud/offers/{id}/confirm":
		path = "/v1/cloud/offers/" + url.PathEscape(r.PathValue("id")) + "/confirm"
	case "POST /api/cloud/operations/{id}/action":
		path = "/v1/cloud/operations/" + url.PathEscape(r.PathValue("id")) + "/action"
	default:
		http.NotFound(w, r)
		return
	}
	var input map[string]any
	if r.Method == "POST" {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if json.NewDecoder(r.Body).Decode(&input) != nil {
			memberHTTPError(w, 400)
			return
		}
		if input == nil {
			input = map[string]any{}
		}
		input["actor"] = actor.user.ID
	}
	var result json.RawMessage
	status, e := b.relayJSON(r.Context(), r.Method, path, input, &result)
	if e != nil {
		var failure relayCloudError
		if errors.As(e, &failure) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": failure.Code, "message": cloud.ErrorMessage(failure.Code)})
			return
		}
		memberHTTPError(w, status)
		return
	}
	jsonOK(w, result)
}
