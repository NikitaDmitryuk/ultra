package config

import (
	"encoding/json"
	"testing"
)

func TestDatabaseSpecOptionalPhysicalHost(t *testing.T) {
	for _, input := range []string{
		`{"dsn":"postgres://fixture@127.0.0.1:25432/fixture"}`,
		`{"dsn":"postgres://fixture@127.0.0.1:25432/fixture","primary_host":"192.0.2.40"}`,
	} {
		var spec DatabaseSpec
		if err := json.Unmarshal([]byte(input), &spec); err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		if string(encoded) != input {
			t.Fatalf("database metadata changed across round trip: %s", encoded)
		}
	}
}
