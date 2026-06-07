package exits

// AddParams for creating an exit node via Admin API or bootstrap.
type AddParams struct {
	ID                   string
	Name                 string
	Address              string
	Port                 int
	TunnelUUID           string
	PinnedPeerCertSHA256 string
	Priority             int
	Enabled              *bool
}
