package cloudinstall

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/cloud"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func openDeleteTestDB(t *testing.T) *db.DB {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set")
	}
	ctx := context.Background()
	control, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	schema := pgx.Identifier{"cloud_delete_test_" + uuid.NewString()}.Sanitize()
	if _, err := control.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := control.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
		if err := control.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		q.Set("search_path", schema)
		u.RawQuery = q.Encode()
		dsn = u.String()
	} else {
		dsn += " search_path='" + schema + "'"
	}
	database, err := db.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	return database
}

func TestValidateDeletePaidVPSWithReusedHistoricalAddress(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "saved_address", true: "legacy"}[legacy], func(t *testing.T) {
			database := openDeleteTestDB(t)
			ctx := context.Background()
			repo := db.NewExitNodeRepo(database)
			disabled := false
			oldID := uuid.NewString()
			node, err := repo.Add(
				ctx,
				exits.AddParams{ID: oldID, Name: "historical", Address: "192.0.2.88", Port: 8443, Enabled: &disabled},
			)
			if err != nil {
				t.Fatal(err)
			}
			store := db.NewCloudRepo(database)
			if err := store.SaveOffer(ctx, cloud.Offer{ID: oldID, Actor: 1, ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
			old := cloud.Operation{
				ID:               oldID,
				ExitID:           oldID,
				InstanceID:       "old-instance",
				State:            "deleted",
				Phase:            "cleanup",
				RetirementTarget: node.Address,
			}
			if legacy {
				old.RetirementTarget = ""
			}
			body, err := json.Marshal(old)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := database.Pool.Exec(ctx, `INSERT INTO cloud_operations(id,state,body) VALUES($1,$2,$3)`, old.ID, old.State, body); err != nil {
				t.Fatal(err)
			}
			instance := cloud.Instance{ID: "new-instance", IP: node.Address}
			var missing atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if missing.Load() {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]cloud.Instance{"instance": instance})
			}))
			defer server.Close()
			api := cloud.NewVultr("test")
			api.BaseURL = server.URL
			p := &Provisioner{
				DB:       database,
				API:      api,
				Bridge:   &config.Spec{Database: &config.DatabaseSpec{PrimaryHost: "192.0.2.1"}},
				BridgeIP: "192.0.2.2",
			}
			p.Bridge.Exit.Address = "192.0.2.3"
			for _, phase := range []string{"unpublish", "delete", "cleanup"} {
				for _, absent := range []bool{false, true} {
					missing.Store(absent)
					op := cloud.Operation{
						ID:               uuid.NewString(),
						InstanceID:       instance.ID,
						State:            "pending",
						Phase:            phase,
						Charged:          true,
						RetirementTarget: node.Address,
					}
					if err := p.ValidateDelete(ctx, &op); err != nil {
						t.Fatalf("paid uninstalled VPS delete blocked phase=%s missing=%t: %v", phase, absent, err)
					}
					// The exact same host is still forbidden for explicit retirement.
					op.Phase = "retire_delete"
					if err := p.ValidateRetirement(ctx, &op, instance); !errors.Is(err, cloud.ErrConflict) {
						t.Fatalf("explicit retirement relaxed: %v", err)
					}
				}
			}
			// The exception must never bypass physical infrastructure protection.
			p.Bridge.Database.PrimaryHost = node.Address
			op := cloud.Operation{ID: uuid.NewString(), InstanceID: instance.ID, Phase: "delete", RetirementTarget: node.Address}
			if err := p.ValidateDelete(ctx, &op); !errors.Is(err, cloud.ErrConflict) {
				t.Fatalf("primary protection relaxed: %v", err)
			}
		})
	}
}
