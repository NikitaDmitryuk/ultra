package main

type retainedBridgeExit struct {
	FenceSHA256       string `json:"fence_sha256"`
	SourceSHA256      string `json:"source_sha256"`
	SpecSHA256        string `json:"spec_sha256"`
	CertificateSHA256 string `json:"certificate_sha256"`
	TunnelUUID        string `json:"tunnel_uuid"`
}

func retainedInventoryHost(in retainedPrimaryRebuildInput, group, host string) map[string]any {
	all, _ := in.Inventory["all"].(map[string]any)
	groups, _ := all["children"].(map[string]any)
	g, _ := groups[group].(map[string]any)
	hosts, _ := g["hosts"].(map[string]any)
	h, _ := hosts[host].(map[string]any)
	return h
}
