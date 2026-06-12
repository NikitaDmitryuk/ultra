package exits

// AddParams for creating an exit node via Admin API or bootstrap.
type AddParams struct {
	ID                   string
	Name                 string
	Address              string
	Port                 int
	TunnelUUID           string
	PinnedPeerCertSHA256 string
	CountryCode          string
	CountryName          string
	City                 string
	DisplayName          string
	Priority             int
	Enabled              *bool
}
