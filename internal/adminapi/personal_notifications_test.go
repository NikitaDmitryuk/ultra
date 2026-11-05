package adminapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NikitaDmitryuk/ultra/internal/db"
)

func TestPersonalNotificationPendingPreparationDefersWithoutFailure(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		want    int
		pending bool
	}{
		{"confirmation", db.ErrPersonalNotificationPending, http.StatusOK, true},
		{"unexpected failure", errors.New("database unavailable"), http.StatusServiceUnavailable, false},
		{"superseded", nil, http.StatusOK, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			personalPreparationJSON(w, db.PersonalNotification{ID: 3, Attempts: 100, DeliveryAttempts: 1}, false, "", tc.err)
			if w.Code != tc.want {
				t.Fatalf("status=%d want%d", w.Code, tc.want)
			}
			if w.Code != http.StatusOK {
				return
			}
			var body struct {
				Eligible, Pending bool
				Notification      db.PersonalNotification
			}
			if e := json.Unmarshal(w.Body.Bytes(), &body); e != nil {
				t.Fatal(e)
			}
			if body.Eligible || body.Pending != tc.pending || body.Notification.Attempts != 100 || body.Notification.DeliveryAttempts != 1 {
				t.Fatalf("wrong prepare contract: %+v", body)
			}
		})
	}
}

func TestPersonalDeferredCompletionRejectsSentAndTerminal(t *testing.T) {
	// Rejected bodies must never touch PostgreSQL. A nonnil uninitialized repo
	// establishes that validation happens before invoking its methods.
	s := &Server{PersonalNotifications: db.NewPersonalNotificationRepo(nil)}
	for _, body := range []string{
		`{"notification":{"id":1,"attempts":1},"deferred":true,"sent":true}`,
		`{"notification":{"id":1,"attempts":1},"deferred":true,"terminal":true}`,
		`{"notification":{"id":1,"attempts":1},"sent":true,"terminal":true}`,
	} {
		r := httptest.NewRequest("POST", "/v1/personal-notifications/1/complete", strings.NewReader(body))
		r.SetPathValue("id", "1")
		w := httptest.NewRecorder()
		s.personalComplete(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("unsafe completion accepted: %s status%d", body, w.Code)
		}
	}
}
