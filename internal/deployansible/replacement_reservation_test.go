package deployansible

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func reservationFixture(t *testing.T) (string, string, ReplacementBinding) {
	t.Helper()
	root, _ := executionFixture(t)
	state := filepath.Join(root, "replacement-new")
	job := filepath.Join(state, "bootstrap", "plan", "attempt", "job")
	if err := os.MkdirAll(filepath.Dir(job), 0700); err != nil {
		t.Fatal(err)
	}
	prepareExecutionFixture(t, job)
	return root, job, ReplacementBinding{Workspace: state, TargetsSHA256: strings.Repeat("a", 64), PrimarySHA256: strings.Repeat("b", 64)}
}

func TestReplacementReservationBlocksRealDispatchAndAllowsAuthenticatedChild(t *testing.T) {
	if os.Getenv("ULTRA_RESERVATION_TEST_CHILD") == "1" {
		root := os.Getenv("ULTRA_RESERVATION_TEST_ROOT")
		executionFenceDirectory = func(string) string { return root }
		job := os.Getenv("ULTRA_RESERVATION_TEST_JOB")
		state := os.Getenv("ULTRA_RESERVATION_TEST_STATE")
		ctx, closeLease, err := ImportReplacementReservation(context.Background(), state)
		if os.Getenv("ULTRA_RESERVATION_EXPECT_DENIED") == "1" {
			if !errors.Is(err, ErrReplacementReserved) {
				t.Fatalf("forged child grant accepted: %v", err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		defer closeLease()
		probe := exec.CommandContext(ctx, "/bin/true")
		if err = RetainReplacementSSH(ctx, probe); err != nil {
			t.Fatal(err)
		}
		if err = probe.Run(); err != nil {
			t.Fatal(err)
		}
		if _, err = beginExecutionContext(ctx, job); err != nil {
			t.Fatal(err)
		}
		return
	}
	root, job, binding := reservationFixture(t)
	ctx, lease, err := ReserveReplacement(context.Background(), binding, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.Close() }()
	if _, err = beginExecution(job); !errors.Is(err, ErrReplacementReserved) {
		t.Fatalf("ungranted dispatch: %v", err)
	}
	if err = PreflightLocalExecution(); !errors.Is(err, ErrReplacementReserved) {
		t.Fatalf("preflight: %v", err)
	}
	if _, _, err = ReserveReplacement(ctx, binding, nil); !errors.Is(err, ErrReplacementReserved) {
		t.Fatalf("competing reservation: %v", err)
	}
	if err = lease.SetPhase("mutating"); err != nil {
		t.Fatal(err)
	}
	if _, err = beginExecution(job); !errors.Is(err, ErrReplacementReserved) {
		t.Fatalf("cleanup dispatch: %v", err)
	}
	if err = lease.SetPhase("bootstrap"); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestReplacementReservationBlocksRealDispatchAndAllowsAuthenticatedChild$")
	child.Env = append(
		os.Environ(),
		"ULTRA_RESERVATION_TEST_CHILD=1",
		"ULTRA_RESERVATION_TEST_ROOT="+root,
		"ULTRA_RESERVATION_TEST_JOB="+job,
		"ULTRA_RESERVATION_TEST_STATE="+filepath.Join(binding.Workspace, "bootstrap"),
		replacementDescriptorEnv+"=999",
		replacementIdentityEnv+"=wrong",
	)
	if err = lease.Handoff(child); err != nil {
		t.Fatal(err)
	}
	if raw, err := child.CombinedOutput(); err != nil {
		t.Fatalf("child: %v %s", err, raw)
	}
	if _, err = beginExecution(job); !errors.Is(err, ErrReplacementReserved) {
		t.Fatalf("handoff dispatch: %v", err)
	}
	for _, forged := range []string{"wrong-id", "wrong-workspace", "independent-description"} {
		child := exec.Command(os.Args[0], "-test.run=^TestReplacementReservationBlocksRealDispatchAndAllowsAuthenticatedChild$")
		child.Env = append(
			os.Environ(),
			"ULTRA_RESERVATION_TEST_CHILD=1",
			"ULTRA_RESERVATION_EXPECT_DENIED=1",
			"ULTRA_RESERVATION_TEST_ROOT="+root,
			"ULTRA_RESERVATION_TEST_JOB="+job,
			"ULTRA_RESERVATION_TEST_STATE="+filepath.Join(binding.Workspace, "bootstrap"),
		)
		if err = lease.Handoff(child); err != nil {
			t.Fatal(err)
		}
		switch forged {
		case "wrong-id":
			for i, entry := range child.Env {
				if strings.HasPrefix(entry, replacementIdentityEnv+"=") {
					child.Env[i] = replacementIdentityEnv + "=" + strings.Repeat("f", 32)
				}
			}
		case "wrong-workspace":
			for i, entry := range child.Env {
				if strings.HasPrefix(entry, "ULTRA_RESERVATION_TEST_STATE=") {
					child.Env[i] = "ULTRA_RESERVATION_TEST_STATE=" + filepath.Join(root, "other", "bootstrap")
				}
			}
		case "independent-description":
			file, openErr := os.OpenFile(filepath.Join(root, replacementLockName), os.O_RDWR, 0600)
			if openErr != nil {
				t.Fatal(openErr)
			}
			defer func() { _ = file.Close() }()
			child.ExtraFiles[0] = file
		}
		if raw, runErr := child.CombinedOutput(); runErr != nil {
			t.Fatalf("%s: %v %s", forged, runErr, raw)
		}
	}
	if err = lease.Finish(); err != nil {
		t.Fatal(err)
	}
}

func TestReplacementReservationFailedNativeMutationRemainsAndExactTakeover(t *testing.T) {
	root, job, binding := reservationFixture(t)
	_, lease, err := ReserveReplacement(context.Background(), binding, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.SetPhase("mutating"); err != nil {
		t.Fatal(err)
	}
	if lease.SafeToFinish() {
		t.Fatal("uncertain remote mutation considered safe")
	}
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = beginExecution(job); !errors.Is(err, ErrReplacementReserved) {
		t.Fatalf("durable dispatch: %v", err)
	}
	if _, _, err = ReserveReplacement(context.Background(), binding, func(ReplacementReservation) error { return nil }); !errors.Is(
		err,
		ErrReplacementReserved,
	) {
		t.Fatalf("live owner reclaimed: %v", err)
	}
	record, err := inspectReplacementReservation(root)
	if err != nil {
		t.Fatal(err)
	}
	// A reaped real process supplies an absent PID, avoiding assumptions about PID limits.
	dead := exec.Command("true")
	if err = dead.Run(); err != nil {
		t.Fatal(err)
	}
	record.PID = dead.Process.Pid
	record.Start = "old-start"
	if err = replaceReservationRecord(root, *record); err != nil {
		t.Fatal(err)
	}
	denied := errors.New("scope mismatch")
	if _, _, err = ReserveReplacement(context.Background(), binding, func(ReplacementReservation) error { return denied }); !errors.Is(
		err,
		denied,
	) {
		t.Fatalf("scope validation: %v", err)
	}
	_, next, err := ReserveReplacement(context.Background(), binding, func(actual ReplacementReservation) error {
		if actual != *record {
			t.Fatal("wrong prior reservation")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = next.Close() }()
	if _, err = os.Stat(filepath.Join(root, "replacement-reservation.superseded-"+record.ID+".json")); err != nil {
		t.Fatal(err)
	}
	if err = next.Finish(); err != nil {
		t.Fatal(err)
	}
	if err = next.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = beginExecution(job); err != nil {
		t.Fatalf("corrected attempt blocked: %v", err)
	}
}

func TestReplacementReservationParentDeathKeepsChildLock(t *testing.T) {
	root, _, binding := reservationFixture(t)
	_, lease, err := ReserveReplacement(context.Background(), binding, nil)
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command("sleep", "2")
	child.ExtraFiles = []*os.File{lease.file}
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	// Closing the parent's reference models abrupt death; the inherited open
	// file description must continue excluding a new reservation.
	if err = lease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err = ReserveReplacement(context.Background(), binding, func(ReplacementReservation) error { t.Fatal("validated while child lock alive"); return nil }); !errors.Is(
		err,
		ErrReplacementReserved,
	) {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(root, replacementRecordName)); err != nil {
		t.Fatal(err)
	}
}

func TestReplacementReservationRejectsEnvironmentOnlyGrant(t *testing.T) {
	_, _, binding := reservationFixture(t)
	t.Setenv(replacementDescriptorEnv, "999999")
	t.Setenv(replacementIdentityEnv, strings.Repeat("a", 32))
	if _, _, err := ImportReplacementReservation(context.Background(), filepath.Join(binding.Workspace, "bootstrap")); !errors.Is(
		err,
		ErrReplacementReserved,
	) {
		t.Fatal(err)
	}
}

func TestReplacementSSHGuardRetainsLockAndPreservesExit(t *testing.T) {
	_, _, binding := reservationFixture(t)
	ctx, lease, err := ReserveReplacement(context.Background(), binding, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lease.Close() }()
	command := exec.CommandContext(ctx, "/bin/sh", "-c", "cat; printf error >&2; exit 7")
	command.Stdin = strings.NewReader("literal stdin")
	if err = RetainReplacementSSH(ctx, command); err != nil {
		t.Fatal(err)
	}
	raw, err := command.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 || string(raw) != "literal stdinerror" {
		t.Fatalf("output/exit changed: %q %v", raw, err)
	}
	if err = lease.Finish(); err != nil {
		t.Fatal(err)
	}
}

func TestReplacementSSHGuardSurvivesKilledOwnerAndIsBounded(t *testing.T) {
	const helper = "ULTRA_RESERVATION_OWNER_TEST"
	if os.Getenv(helper) == "1" {
		root := os.Getenv("ULTRA_RESERVATION_OWNER_ROOT")
		executionFenceDirectory = func(string) string { return root }
		binding := ReplacementBinding{
			Workspace:     filepath.Join(root, "replacement-new"),
			TargetsSHA256: strings.Repeat("a", 64),
			PrimarySHA256: strings.Repeat("b", 64),
		}
		ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
		defer cancel()
		ctx, lease, err := ReserveReplacement(ctx, binding, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = lease.SetPhase("mutating"); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, "/bin/sleep", "30")
		if err = RetainReplacementSSH(ctx, command); err != nil {
			t.Fatal(err)
		}
		if err = command.Start(); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(root, "owner-ready"), []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(30 * time.Second)
		return
	}
	root, _, binding := reservationFixture(t)
	owner := exec.Command(os.Args[0], "-test.run=^TestReplacementSSHGuardSurvivesKilledOwnerAndIsBounded$")
	owner.Env = append(os.Environ(), helper+"=1", "ULTRA_RESERVATION_OWNER_ROOT="+root)
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = owner.Process.Kill(); _ = owner.Wait() }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "owner-ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("owner did not start supervisor")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := owner.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = owner.Wait()
	if _, _, err := ReserveReplacement(context.Background(), binding, func(ReplacementReservation) error { t.Fatal("live orphan supervisor bypassed"); return nil }); !errors.Is(
		err,
		ErrReplacementReserved,
	) {
		t.Fatal(err)
	}
	// The supervisor's own deadline survives its parent and kills its entire
	// process group. The durable record still requires canonical scope proof.
	deadline = time.Now().Add(4 * time.Second)
	for {
		_, next, err := ReserveReplacement(context.Background(), binding, func(ReplacementReservation) error { return nil })
		if err == nil {
			defer func() { _ = next.Close() }()
			if next.SafeToFinish() {
				t.Fatal("takeover erased previous remote uncertainty")
			}
			if err = next.Finish(); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("orphan remained indefinitely: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestReplacementReservationMalformedMarkerIsPurelyRejected(t *testing.T) {
	for _, invalid := range []string{"json", "id-path", "targets-hash", "phase"} {
		t.Run(invalid, func(t *testing.T) {
			root, _, binding := reservationFixture(t)
			_, lease, err := ReserveReplacement(context.Background(), binding, nil)
			if err != nil {
				t.Fatal(err)
			}
			record := lease.record
			if err = lease.Close(); err != nil {
				t.Fatal(err)
			}
			switch invalid {
			case "id-path":
				record.ID = strings.Repeat("../", 10) + "aa"
			case "targets-hash":
				record.Binding.TargetsSHA256 = strings.Repeat("z", 64)
			case "phase":
				record.Phase = "complete"
			}
			if invalid == "json" {
				err = os.WriteFile(filepath.Join(root, replacementRecordName), []byte("{"), 0600)
			} else {
				err = replaceReservationRecord(root, record)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := preflightSnapshot(t, root)
			if err = PreflightLocalExecution(); !errors.Is(err, ErrReplacementReserved) {
				t.Fatal(err)
			}
			if after := preflightSnapshot(t, root); !reflect.DeepEqual(before, after) {
				t.Fatal("read-only preflight changed marker")
			}
			if _, _, err = ReserveReplacement(context.Background(), binding, func(ReplacementReservation) error { t.Fatal("malformed marker reached scope proof"); return nil }); !errors.Is(
				err,
				ErrReplacementReserved,
			) {
				t.Fatal(err)
			}
		})
	}
}
