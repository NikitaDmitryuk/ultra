package auth

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
)

type preferenceRepo struct {
	DBUserRepo
	exit *string
}

func (r *preferenceRepo) SetPreferredExit(_ context.Context, id string, exit *string) (User, error) {
	r.exit = exit
	return User{UUID: id, PreferredExitID: exit}, nil
}
func TestPreferenceCannotReportSuccessWhenApplicationFails(t *testing.T) {
	repo := &preferenceRepo{}
	manager := &DBManager{repo: repo, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	calls := 0
	manager.ApplyChange = func([]User) error { calls++; return errors.New("fixture") }
	exit := "atl"
	if _, err := manager.SetPreferredExit("owner", &exit); !errors.Is(err, ErrRouteApply) {
		t.Fatal(err)
	}
	if calls != 1 || repo.exit == nil || *repo.exit != "atl" {
		t.Fatal("desired route lost or apply duplicated")
	}
	manager.ApplyChange = func([]User) error { calls++; return nil }
	if _, err := manager.SetPreferredExit("owner", &exit); err != nil || calls != 2 {
		t.Fatal("retry failed", err)
	}
}
