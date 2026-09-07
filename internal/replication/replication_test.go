package replication

import "testing"

func TestReplicaSpaceReserve(t *testing.T) {
	for _, test := range []struct{ size, want int64 }{{0, 5 * GiB}, {GiB, 5 * GiB}, {3 * GiB, 8 * GiB}, {10 * GiB, 22 * GiB}} {
		if got := RequiredFreeBytes(test.size); got != test.want {
			t.Fatalf("reserve %d: got %d want %d", test.size, got, test.want)
		}
	}
}
