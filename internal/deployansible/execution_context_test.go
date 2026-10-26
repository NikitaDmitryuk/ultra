package deployansible

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestExecutionStateConfigurationIsAccountBoundAndPrivate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged account fixture")
	}
	root, err := os.MkdirTemp(".", ".execution-account-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root) //nolint:errcheck
	home, err := filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	oldLookup := lookupExecutionAccount
	lookupExecutionAccount = func(string) (*user.User, error) { return &user.User{HomeDir: home}, nil }
	t.Cleanup(func() { lookupExecutionAccount = oldLookup })
	localExecutionState.Lock()
	oldState := localExecutionState.path
	localExecutionState.path = ""
	localExecutionState.Unlock()
	t.Cleanup(func() { localExecutionState.Lock(); localExecutionState.path = oldState; localExecutionState.Unlock() })
	expected := filepath.Join(home, ".local/state/ultra-ansible")
	if err = requireConfiguredExecutionState(); err == nil {
		t.Fatal("implicit namespace accepted")
	}
	for _, invalid := range []string{"relative", filepath.Join(home, "different"), expected + "/../ultra-ansible"} {
		if err = ConfigureLocalExecutionState(invalid); err == nil {
			t.Fatalf("alternate namespace accepted: %s", invalid)
		}
	}
	if err = ConfigureLocalExecutionState(expected); err != nil {
		t.Fatal(err)
	}
	if err = requireConfiguredExecutionState(); err != nil {
		t.Fatal(err)
	}
	if info, e := os.Stat(expected); e != nil || info.Mode().Perm() != 0700 {
		t.Fatal(info, e)
	}
	if err = os.Chmod(expected, 0755); err != nil {
		t.Fatal(err)
	}
	if err = requireConfiguredExecutionState(); err == nil {
		t.Fatal("nonprivate state admitted")
	}
	if err = os.Remove(expected); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(home, expected); err != nil {
		t.Fatal(err)
	}
	if err = ConfigureLocalExecutionState(expected); err == nil {
		t.Fatal("symlink namespace admitted")
	}
}

func TestUserContainmentProofBindsUIDManagerAndCgroup(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged account fixture")
	}
	_, proof := containmentCompletionFixture(t)
	proof.Schema, proof.Manager, proof.UID = 2, "user", os.Geteuid()
	group, err := executionUnitGroup(proof.Unit, "")
	if err != nil {
		t.Fatal(err)
	}
	proof.ControlGroup = group
	proof.Chain[0].Group = group
	mockContainmentObservation(t, func(string) (map[string]string, error) { return map[string]string{"LoadState": "not-found"}, nil })
	if err = verifyContainmentProof(proof); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*containmentProof){
		func(p *containmentProof) { p.UID++ },
		func(p *containmentProof) { p.Manager = "system" },
		func(p *containmentProof) { p.ControlGroup = "/system.slice/" + p.Unit },
		func(p *containmentProof) { p.Chain[0].Group = "/foreign" },
		func(p *containmentProof) { p.Unit = "../foreign.service" },
	} {
		changed := proof
		changed.Chain = append([]containmentProcess(nil), proof.Chain...)
		mutate(&changed)
		if err = verifyContainmentProof(changed); err == nil {
			t.Fatal("foreign user containment accepted")
		}
	}
	uid := strconv.Itoa(os.Geteuid())
	if !strings.HasPrefix(group, "/user.slice/user-"+uid+".slice/user@"+uid+".service/app.slice/") {
		t.Fatal(group)
	}
}

func TestUserImportedLegacyDrainDoesNotNeedRootManagerAuthority(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unprivileged account fixture")
	}
	fence, proof := containmentCompletionFixture(t)
	if err := persistVerifiedContainment(proof); err != nil {
		t.Fatal(err)
	}
	resolver := executionFenceDirectory
	executionFenceDirectory = productionExecutionFenceDirectory
	t.Cleanup(func() { executionFenceDirectory = resolver })
	if err := validateExecutionContainment(*fence); err != nil {
		t.Fatal(err)
	}
	if err := verifyContainmentProof(proof); err == nil {
		t.Fatal("user manager acquired root worker authority")
	}
	if err := os.Remove(filepath.Join(fence.JobDirectory, "execution-drain-"+fence.Generation+".json")); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutionContainment(*fence); err == nil {
		t.Fatal("undrained historical root proof accepted")
	}
}
