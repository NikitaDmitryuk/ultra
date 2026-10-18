package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/config"
)

func TestDeploymentDatabaseStatusPhysicalHostMetadata(t *testing.T) {
	for _, host := range []string{"", "192.0.2.40"} {
		spec := &config.Spec{Database: &config.DatabaseSpec{PrimaryHost: host}}
		got := deploymentDatabaseStatus(context.Background(), nil, spec)
		if got.ObservedRole != "unknown" || got.Reachable {
			t.Fatal("deployment metadata was used as live SQL health")
		}
		if host == "" {
			data, _ := json.Marshal(got)
			if got.PrimaryHost != nil || !strings.Contains(string(data), `"primary_host":null`) {
				t.Fatal("legacy deployment did not report unknown physical host")
			}
		} else if got.PrimaryHost == nil || *got.PrimaryHost != host {
			t.Fatal("physical host lost while SQL probe unavailable")
		}
	}
}
