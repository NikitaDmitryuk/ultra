package install

import (
	"strings"
	"testing"
)

func TestRTCServiceOptionalAndIsolation(t *testing.T) {
	var off *RTCServiceDeployment
	if e := off.Validate(); e != nil || off.Spec().Enabled {
		t.Fatal("absent flag requires files")
	}
	disabled := &RTCServiceDeployment{ContentFile: "/nonexistent"}
	if e := disabled.Validate(); e != nil {
		t.Fatal(e)
	}
	unit := RTCServiceUnit(12001, 999)
	for _, v := range []string{"User=ultra-rtc", "NoNewPrivileges=true", "AF_NETLINK", "MemoryMax=2G", "CPUQuota=200%", "StandardOutput=null", "-relay-uid 999"} {
		if !strings.Contains(unit, v) {
			t.Fatal("missing isolation", v)
		}
	}
	if strings.Contains(unit, "EnvironmentFile") {
		t.Fatal("relay environment inherited")
	}
}
