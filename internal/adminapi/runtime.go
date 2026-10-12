package adminapi

import "net/http"

// Handler permits the relay's always-on diagnostic listener to mount control
// endpoints after PostgreSQL becomes available without replacing the listener.
func (s *Server) Handler() http.Handler { return s.srv.Handler }
