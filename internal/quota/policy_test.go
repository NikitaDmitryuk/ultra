package quota

import "testing"

func TestDemandAllocationDoesNotReserveForIdleUsers(t *testing.T) {
	active := []Demand{{ID: "frequent", Recent: 100 * GiB}, {ID: "occasional", Recent: GiB}}
	before := Allocate(100*GiB, active)
	for i := 0; i < 1000; i++ {
		active = append(active, Demand{ID: string(rune(i + 1000))})
	}
	after := Allocate(100*GiB, active)
	if after["frequent"] != before["frequent"] || after["occasional"] != before["occasional"] {
		t.Fatal("idle users reserved bandwidth")
	}
	if after["frequent"] <= after["occasional"] {
		t.Fatal("demand ignored")
	}
	if after["frequent"] >= 100*GiB {
		t.Fatal("frequent user monopolizes pool")
	}
}
func TestAllowanceNeverExceedsRemainingPool(t *testing.T) {
	for _, pool := range []int64{-1, 0, 1, GiB, 100 * GiB} {
		for _, v := range Allocate(pool, []Demand{{ID: "new"}, {ID: "active", Recent: GiB}}) {
			if v < 0 || v > max(0, pool) {
				t.Fatalf("invalid allowance %d for %d", v, pool)
			}
		}
	}
}
