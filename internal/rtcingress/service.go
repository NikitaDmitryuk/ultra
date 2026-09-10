package rtcingress

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/db"
	"github.com/NikitaDmitryuk/ultra/internal/rtc"
	"github.com/NikitaDmitryuk/ultra/internal/rtcsupervisor"
	"github.com/NikitaDmitryuk/ultra/internal/subscriptionkey"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrInvalidRoom = errors.New("invalid_room")
var ErrUnavailable = errors.New("unavailable")

type Secret struct{ Provider, Room, Key, Password string }
type Service struct {
	mu           sync.Mutex
	indexCipher  []byte
	indexVersion string
	Repo         *db.RTCRepo
	Keys         *subscriptionkey.Ring
	Content      *rtc.PrivateContent
	Gateway      *Gateway
	Supervisor   rtcsupervisor.Client
	sessions     map[string]rtcsupervisor.Session
}

func New(repo *db.RTCRepo, keys *subscriptionkey.Ring, content *rtc.PrivateContent, dial DialFunc, socket string) *Service {
	s := &Service{Repo: repo, Keys: keys, Content: content, Supervisor: rtcsupervisor.Client{Socket: socket}, sessions: map[string]rtcsupervisor.Session{}}
	s.Gateway = NewGateway(dial, repo.Eligible)
	u, _ := url.Parse(content.ProbeURL)
	if u != nil {
		port := u.Port()
		if port == "" {
			port = "443"
		}
		s.Gateway.ProbeAddress = net.JoinHostPort(u.Hostname(), port)
	}
	return s
}
func randomSecret() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return hex.EncodeToString(b), e
}
func (s *Service) open(a db.RTCAccess) (Secret, error) {
	var secret Secret
	plain, e := s.Keys.Open("rtc/config/"+a.Owner, a.Cipher, a.KeyVersion)
	if e != nil {
		return secret, ErrUnavailable
	}
	if json.Unmarshal([]byte(plain), &secret) != nil {
		return secret, ErrUnavailable
	}
	return secret, nil
}
func (s *Service) seal(owner string, v Secret) (db.RTCAccess, error) {
	a := db.RTCAccess{Owner: owner, Generation: uuid.NewString()}
	b, e := json.Marshal(v)
	if e != nil {
		return a, e
	}
	a.Cipher, a.KeyVersion, e = s.Keys.Seal("rtc/config/"+owner, string(b))
	if e != nil {
		return a, e
	}
	// A keyed room fingerprint permits uniqueness without exposing a guessable room ID.
	key, e := s.Keys.Open("rtc/room-index", s.indexCipher, s.indexVersion)
	if e != nil {
		return a, e
	}
	h := hmac.New(sha256.New, []byte(key))
	_, _ = h.Write([]byte(v.Provider + ":" + v.Room))
	a.RoomHash = h.Sum(nil)
	return a, nil
}
func (s *Service) Initialize(ctx context.Context, port int, legacy []rtc.Binding) error {
	key, e := randomSecret()
	if e != nil {
		return e
	}
	cipher, version, e := s.Keys.Seal("rtc/room-index", key)
	if e != nil {
		return e
	}
	s.indexCipher, s.indexVersion, e = s.Repo.IndexKey(ctx, cipher, version)
	if e != nil {
		return e
	}
	for _, b := range legacy {
		if !b.Enabled || !s.Repo.Eligible(ctx, b.UserUUID) {
			continue
		}
		if _, e = s.Repo.Get(ctx, b.UserUUID); e == nil {
			continue
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		k, e := rtc.ReadSecret(b.KeyFile)
		if e != nil {
			return e
		}
		pass, e := rtc.ReadSecret(b.PasswordFile)
		if e != nil {
			return e
		}
		a, e := s.seal(b.UserUUID, Secret{b.Provider, b.RoomID, k, pass})
		if e != nil {
			return e
		}
		if _, e = s.Repo.Put(ctx, a, s.Content.MaxAccesses, true); e != nil {
			return e
		}
	}
	l, e := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if e != nil {
		return errors.New("rtc gateway unavailable")
	}
	s.Gateway.listener = l
	go s.Gateway.Serve(l)
	return nil
}
func (s *Service) Put(ctx context.Context, owner, raw string, retry bool) (db.RTCAccess, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, e := s.Repo.Get(ctx, owner)
	var secret Secret
	if retry {
		if e != nil || !old.Enabled {
			return old, ErrUnavailable
		}
		secret, e = s.open(old)
		if e != nil {
			return old, e
		}
	} else {
		provider, room, e := s.Content.ParseRoom(raw)
		if e != nil {
			return old, ErrInvalidRoom
		}
		if old.Owner != "" && old.Enabled {
			v, e := s.open(old)
			if e != nil {
				return old, e
			}
			if v.Provider == provider && v.Room == room {
				return old, nil
			}
		}
		secret = Secret{Provider: provider, Room: room}
	}
	secret.Key, e = randomSecret()
	if e != nil {
		return old, e
	}
	secret.Password, e = randomSecret()
	if e != nil {
		return old, e
	}
	a, e := s.seal(owner, secret)
	if e != nil {
		return a, e
	}
	a, e = s.Repo.Put(ctx, a, s.Content.MaxAccesses, false)
	if e != nil {
		return a, e
	}
	s.Gateway.Revoke(owner)
	delete(s.sessions, owner)
	// Synchronize removal before returning: old peers cannot keep reaching the gateway.
	_ = s.reconcileLocked(ctx)
	return a, nil
}
func (s *Service) Delete(ctx context.Context, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e := s.Repo.Disable(ctx, owner); e != nil {
		return e
	}
	s.Gateway.Revoke(owner)
	delete(s.sessions, owner)
	return s.reconcileLocked(ctx)
}
func (s *Service) Profile(ctx context.Context, owner string) (string, error) {
	a, e := s.Repo.Get(ctx, owner)
	if e != nil || !a.Enabled || a.State != "ready" || !s.Repo.Eligible(ctx, owner) {
		return "", ErrUnavailable
	}
	v, e := s.open(a)
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("#name: ultra RTC\n#refresh: 1h\nolcrtc://%s?vp8channel<vp8-fps=30&vp8-batch=64>@%s#%s$emergency\n", v.Provider, v.Room, v.Key), nil
}
func (s *Service) Reconcile(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reconcileLocked(ctx)
}
func (s *Service) reconcileLocked(ctx context.Context) error {
	rows, e := s.Repo.List(ctx)
	if e != nil {
		return e
	}
	desired := []rtcsupervisor.Session{}
	owners := map[string]db.RTCAccess{}
	for _, a := range rows {
		active, e := s.Repo.Active(ctx, a.Owner)
		if e != nil {
			return e
		}
		if !active && a.Enabled {
			if e = s.Repo.Disable(ctx, a.Owner); e != nil {
				return e
			}
			a.Enabled = false
		}
		if !a.Enabled || !s.Repo.Eligible(ctx, a.Owner) {
			s.Gateway.Revoke(a.Owner)
			delete(s.sessions, a.Owner)
			continue
		}
		v, e := s.open(a)
		if e != nil {
			s.Gateway.Revoke(a.Owner)
			continue
		}
		session := rtcsupervisor.Session{Generation: a.Generation, Provider: v.Provider, Room: v.Room, Key: v.Key, Username: a.Generation, Password: v.Password}
		if old, ok := s.sessions[a.Owner]; !ok || old != session {
			s.Gateway.Revoke(a.Owner)
		}
		s.sessions[a.Owner] = session
		s.Gateway.Set(a.Generation, credential{Owner: a.Owner, Generation: a.Generation, Password: v.Password, Probe: true})
		desired = append(desired, session)
		owners[a.Generation] = a
	}
	// Also revoke owners deleted by a cascading database mutation.
	for owner, session := range s.sessions {
		if _, ok := owners[session.Generation]; !ok {
			s.Gateway.Revoke(owner)
			delete(s.sessions, owner)
		}
	}
	states, e := s.Supervisor.Sync(ctx, desired)
	if e != nil {
		for _, a := range owners {
			s.Gateway.Revoke(a.Owner)
			_ = s.Repo.Observed(ctx, a.Owner, a.Generation, "recovering", "supervisor_unavailable", nil)
		}
		return e
	}
	for _, st := range states {
		a, ok := owners[st.Generation]
		if !ok {
			continue
		}
		state := "preparing"
		if st.Running {
			state = "checking"
		}
		if st.Error != "" {
			state = "error"
		}
		if st.Ready && st.Running {
			state = "ready"
		}
		if e = s.Repo.Observed(ctx, a.Owner, a.Generation, state, st.Error, st.Checked); e != nil {
			return e
		}
	}
	return nil
}
func (s *Service) Run(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	lastFlush := time.Now()
	defer func() {
		s.Gateway.Close()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.Gateway.Flush(c, s.Repo)
		_, _ = s.Supervisor.Sync(c, nil)
	}()
	for {
		c, cancel := context.WithTimeout(ctx, 15*time.Second)
		_ = s.Reconcile(c)
		if time.Since(lastFlush) >= time.Minute {
			_ = s.Gateway.Flush(c, s.Repo)
			lastFlush = time.Now()
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
