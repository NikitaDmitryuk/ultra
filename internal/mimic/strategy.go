package mimic

// Strategy describes HTTP-layer camouflage for XHTTP / splithttp (host, path, headers).
// Public-edge TLS server name / handshake target are configured separately in the relay spec.
type Strategy interface {
	// Name is the preset id (e.g. apijson).
	Name() string
	Host() string
	// NextPath returns a path for the current xray config generation cycle (static per reload).
	NextPath() string
	ExtraHeaders() map[string]string
}
