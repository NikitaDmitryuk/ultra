// Package exitping serves the local, bodyless HTTP endpoint used by tunneled
// client latency probes. It never opens a public listener.
package exitping

import (
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

const Path = "/generate_204"

// Server owns a loopback listener and its HTTP server.
type Server struct {
	listener net.Listener
	server   *http.Server
}

// Start starts the responder on an OS-assigned IPv4 loopback port.
func Start() (*Server, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	server := &http.Server{
		Handler:           http.HandlerFunc(serve),
		ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       5 * time.Second,
		MaxHeaderBytes:    4096,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	s := &Server{listener: listener, server: server}
	go func() { _ = server.Serve(listener) }()
	return s, nil
}

// Port is runtime state only; it must not be persisted in the installation spec.
func (s *Server) Port() int { return s.listener.Addr().(*net.TCPAddr).Port }

// Close closes the listener and active connections without waiting on slow peers.
func (s *Server) Close() error { return s.server.Close() }

func serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	if r.URL.Path != Path {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
