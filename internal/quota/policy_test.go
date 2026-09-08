package quota

import "testing"

func TestMonthlyCeiling(t *testing.T) {
	const monthly int64 = 1024_000_000_000
	if PersonalLimit(monthly) != 204_800_000_000 {
		t.Fatal("wrong nominal cap")
	}
	for _, tc := range []struct {
		used, shared, want int64
		fallback           bool
	}{
		{0, monthly, 204_800_000_000, false}, {204_800_000_000, monthly, 0, false},
		{1, 10, 10, false}, {0, 0, 0, false}, {monthly, 100, 100, true},
	} {
		if got := Available(monthly, tc.used, tc.shared, tc.fallback); got != tc.want {
			t.Fatalf("%+v: %d", tc, got)
		}
	}
}
