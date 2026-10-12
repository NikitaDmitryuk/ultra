package replication

import (
	"strconv"
	"testing"
	"time"
)

func TestReplicaSpaceReserve(t *testing.T) {
	for _, test := range []struct{ size, want int64 }{{0, 5 * GiB}, {GiB, 5 * GiB}, {3 * GiB, 8 * GiB}, {10 * GiB, 22 * GiB}} {
		if got := RequiredFreeBytes(test.size); got != test.want {
			t.Fatalf("reserve %d: got %d want %d", test.size, got, test.want)
		}
	}
}

func TestHeartbeatRequiresRecentReplay(t *testing.T) {
	now := time.Unix(1800000000, 0)
	for _, tc := range []struct {
		value string
		fresh bool
	}{
		{strconv.FormatInt(now.Unix()-60, 10), true}, {strconv.FormatInt(now.Unix()-301, 10), false},
		{strconv.FormatInt(now.Unix()+60, 10), false}, {"", false}, {"NaN", false}, {"0", false},
	} {
		if heartbeatFresh(tc.value, now) != tc.fresh {
			t.Fatalf("freshness mismatch for %q", tc.value)
		}
	}
}
