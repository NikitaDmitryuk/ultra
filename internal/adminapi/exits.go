package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
)

type postExitReq struct {
	Name     string `json:"name"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Priority int    `json:"priority"`
}

type patchExitReq struct {
	Name     *string `json:"name"`
	Address  *string `json:"address"`
	Port     *int    `json:"port"`
	Priority *int    `json:"priority"`
	Enabled  *bool   `json:"enabled"`
}

type exitDeployHints struct {
	TunnelUUID     string `json:"tunnel_uuid"`
	SplithttpPath  string `json:"splithttp_path"`
	SplithttpHost  string `json:"splithttp_host"`
	TunnelPort     int    `json:"tunnel_port"`
	InstallExample string `json:"install_example"`
}

func (s *Server) deployHints(n exits.Node) exitDeployHints {
	tunnelPort := s.spec.Exit.Port
	if tunnelPort <= 0 {
		tunnelPort = s.spec.VLESSPort
	}
	host := strings.TrimSpace(s.spec.SplithttpHost)
	path := strings.TrimSpace(s.spec.SplithttpPath)
	transport := string(s.spec.TunnelTransport)
	if transport == "" {
		transport = "splithttp"
	}
	example := fmt.Sprintf(
		`ultra-install -exit-only -exit %s -tunnel-uuid %s -tunnel-port %d -transport %s`,
		n.Address, n.TunnelUUID, tunnelPort, transport,
	)
	return exitDeployHints{
		TunnelUUID:     n.TunnelUUID,
		SplithttpPath:  path,
		SplithttpHost:  host,
		TunnelPort:     tunnelPort,
		InstallExample: example,
	}
}

func (s *Server) handleListExits(w http.ResponseWriter, r *http.Request) {
	if s.exits == nil {
		http.Error(w, "exit management requires database backend", http.StatusNotImplemented)
		return
	}
	nodes := s.exits.List()
	type item struct {
		exits.Node
		Active bool `json:"active"`
	}
	enabled := exits.FilterEnabled(nodes)
	activeID := ""
	if s.selector != nil {
		activeID = s.selector.ActiveID()
	}
	activeStillEnabled := false
	for _, n := range enabled {
		if n.ID == activeID {
			activeStillEnabled = true
			break
		}
	}
	if !activeStillEnabled && len(enabled) > 0 {
		candidate, _ := exits.SelectActive(enabled, nil)
		activeID = candidate.ID
	}
	out := make([]item, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, item{Node: n, Active: n.Enabled && n.ID == activeID})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"exits":          out,
		"active_exit_id": activeID,
	})
}

func (s *Server) handlePostExit(w http.ResponseWriter, r *http.Request) {
	if s.exits == nil {
		http.Error(w, "exit management requires database backend", http.StatusNotImplemented)
		return
	}
	var body postExitReq
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	n, err := s.exits.Add(r.Context(), exits.AddParams{
		Name:     body.Name,
		Address:  body.Address,
		Port:     body.Port,
		Priority: body.Priority,
	})
	if err != nil {
		s.writeExitError(w, err)
		return
	}
	if s.onExitChange != nil {
		s.onExitChange()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"exit":   n,
		"deploy": s.deployHints(n),
	})
}

func (s *Server) handlePatchExit(w http.ResponseWriter, r *http.Request) {
	if s.exits == nil {
		http.Error(w, "exit management requires database backend", http.StatusNotImplemented)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	var body patchExitReq
	if !s.decodeAdminJSON(w, r, &body) {
		return
	}
	n, err := s.exits.Update(r.Context(), id, exits.UpdatePatch{
		Name:     body.Name,
		Address:  body.Address,
		Port:     body.Port,
		Priority: body.Priority,
		Enabled:  body.Enabled,
	})
	if err != nil {
		s.writeExitError(w, err)
		return
	}
	if s.onExitChange != nil {
		s.onExitChange()
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"exit": n})
}

func (s *Server) handleDeleteExit(w http.ResponseWriter, r *http.Request) {
	if s.exits == nil {
		http.Error(w, "exit management requires database backend", http.StatusNotImplemented)
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if err := s.exits.Delete(r.Context(), id); err != nil {
		s.writeExitError(w, err)
		return
	}
	if s.onExitChange != nil {
		s.onExitChange()
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) writeExitError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrExitNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, db.ErrExitLastEnabled):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, db.ErrExitDuplicateAddr), errors.Is(err, db.ErrExitDuplicateUUID):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		if isExitValidationError(err) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		s.log.Error("exit api", "err", err)
		http.Error(w, "internal", http.StatusInternalServerError)
	}
}

func isExitValidationError(err error) bool {
	msg := err.Error()
	switch msg {
	case "exit name required", "exit address required", "invalid port", "priority must be positive":
		return true
	default:
		return strings.HasSuffix(msg, " required")
	}
}

func (s *Server) probeExitsHealth(ctx context.Context) (active exits.Node, exitsHealth []exits.Health, activeID string) {
	if s.exits == nil {
		return exits.Node{}, nil, ""
	}
	nodes := s.exits.ListEnabled()
	if s.selector != nil {
		active, _ = s.selector.ProbeAndSelect(ctx, nodes)
		activeID = active.ID
		snap := s.selector.HealthSnapshot()
		for _, n := range nodes {
			h, ok := snap[n.ID]
			if !ok {
				h = exits.Health{ID: n.ID}
			}
			exitsHealth = append(exitsHealth, h)
		}
		return active, exitsHealth, activeID
	}
	if len(nodes) > 0 {
		active = nodes[0]
		activeID = active.ID
	}
	return active, exitsHealth, activeID
}
