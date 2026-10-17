package install

import (
	"strings"
	"testing"
)

func TestRemoteRecoveryRequiresExistingHostKey(t *testing.T) {
	remote := Remote{Host: "192.0.2.2", Identity: "/fixture/identity", KnownHosts: "/fixture/known_hosts", RequireKnownHost: true}
	args, err := remote.args()
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "StrictHostKeyChecking=yes") || strings.Contains(joined, "accept-new") ||
		!strings.Contains(joined, "UserKnownHostsFile=/fixture/known_hosts") {
		t.Fatal("recovery lost prior host identity", joined)
	}
}
