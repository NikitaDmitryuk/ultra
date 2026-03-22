package mimic

// Strategy describes HTTP-layer camouflage for XHTTP / splithttp (host, path, headers).
// TLS/Reality SNI is configured separately in relay-spec (see README).
type Strategy interface {
	// Name is the preset id (e.g. plusgaming).
	Name() string
	Host() string
	// NextPath returns a path for the current xray config generation cycle (static per reload).
	NextPath() string
	ExtraHeaders() map[string]string
}
