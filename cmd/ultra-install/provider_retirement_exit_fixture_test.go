package main

import (
	"strings"
)

func retainedBridgeExitFixture() *retainedBridgeExit {
	return &retainedBridgeExit{
		FenceSHA256:       strings.Repeat("b", 64),
		SourceSHA256:      strings.Repeat("c", 64),
		SpecSHA256:        strings.Repeat("d", 64),
		CertificateSHA256: strings.Repeat("e", 64),
		TunnelUUID:        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
	}
}
