package bot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/subscriptionmeta"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const subscriptionCacheLifetime = 24 * time.Hour
const maxSubscriptionCacheSize = 32 << 20

type cachedSubscription struct {
	Body        []byte            `json:"body"`
	Headers     map[string]string `json:"headers"`
	ConfirmedAt time.Time         `json:"confirmed_at"`
}
type subscriptionCacheSnapshot struct {
	Version         int                           `json:"version"`
	HappDefaultJSON bool                          `json:"happ_default_json,omitempty"`
	BotUsername     string                        `json:"bot_username,omitempty"`
	Entries         map[string]cachedSubscription `json:"entries"`
}
type subscriptionCache struct {
	mu                   sync.RWMutex
	refreshMu            sync.Mutex
	revokedDuringRefresh map[string]struct{}
	revocationOverflow   bool
	path                 string
	entries              map[string]cachedSubscription
	generation           uint64
	happDefaultJSON      bool
	botUsername          string
}

func subscriptionDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}
func subscriptionCacheKey(token, query string) string { return subscriptionDigest(token) + "?" + query }

// ConfigureSubscriptionCache must be called before HTTP or workers start.
func (b *Bot) ConfigureSubscriptionCache(path string) error {
	c := &subscriptionCache{path: path, entries: map[string]cachedSubscription{}}
	b.subscriptionCache = c
	file, err := os.Open(path)
	var data []byte
	if err == nil {
		defer func() { _ = file.Close() }()
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() || info.Size() > maxSubscriptionCacheSize {
			return errors.New("invalid subscription cache file")
		}
		data, err = io.ReadAll(io.LimitReader(file, maxSubscriptionCacheSize+1))
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("subscription cache cannot be read")
	}
	if err == nil {
		var snapshot subscriptionCacheSnapshot
		if len(data) > maxSubscriptionCacheSize || json.Unmarshal(data, &snapshot) != nil || snapshot.Version != 1 {
			return errors.New("invalid subscription cache")
		}
		c.happDefaultJSON = snapshot.HappDefaultJSON
		if validBotUsername(snapshot.BotUsername) {
			c.botUsername = snapshot.BotUsername
		}
		for k, v := range snapshot.Entries {
			if validSubscriptionTime(v.ConfirmedAt, time.Now()) {
				c.entries[k] = v
			}
		}
	}
	b.subscriptionCache = c
	return nil
}
func validSubscriptionTime(at, now time.Time) bool {
	return !at.IsZero() && !now.Before(at) && now.Sub(at) < subscriptionCacheLifetime
}
func (c *subscriptionCache) get(key string) (cachedSubscription, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.entries[key]
	return v, ok && validSubscriptionTime(v.ConfirmedAt, time.Now())
}
func (c *subscriptionCache) fresh() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, v := range c.entries {
		if validSubscriptionTime(v.ConfirmedAt, time.Now()) {
			return true
		}
	}
	return false
}
func (c *subscriptionCache) replace(entries map[string]cachedSubscription) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.replaceLocked(entries)
}
func (c *subscriptionCache) replaceLocked(entries map[string]cachedSubscription) error {
	// Publish memory only after the durable file has been committed.
	data, err := json.Marshal(subscriptionCacheSnapshot{Version: 1, HappDefaultJSON: c.happDefaultJSON, BotUsername: c.botUsername, Entries: entries})
	if err != nil || len(data) > maxSubscriptionCacheSize {
		return errors.New("subscription cache too large")
	}
	if c.path != "" {
		dir := filepath.Dir(c.path)
		if err = os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		f, err := os.CreateTemp(dir, ".subscription-cache-*")
		if err != nil {
			return err
		}
		name := f.Name()
		defer func() { _ = os.Remove(name) }()
		if err = f.Chmod(0600); err == nil {
			_, err = f.Write(data)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		if err = os.Rename(name, c.path); err != nil {
			return err
		}
		d, err := os.Open(dir)
		if err != nil {
			return err
		}
		err = d.Sync()
		_ = d.Close()
		if err != nil {
			return err
		}
	}
	c.entries = entries
	return nil
}

func (c *subscriptionCache) setBotUsername(username string) error {
	if !validBotUsername(username) {
		return errors.New("invalid bot username")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.botUsername == username {
		return nil
	}
	previous := c.botUsername
	c.botUsername = username
	if err := c.replaceLocked(c.entries); err != nil {
		c.botUsername = previous
		return err
	}
	return nil
}
func (c *subscriptionCache) invalidate(digest string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.revokedDuringRefresh != nil {
		if _, known := c.revokedDuringRefresh[digest]; known || len(c.revokedDuringRefresh) < 1024 {
			c.revokedDuringRefresh[digest] = struct{}{}
		} else {
			c.revocationOverflow = true
		}
	}
	entries := make(map[string]cachedSubscription, len(c.entries))
	removed := false
	for k, v := range c.entries {
		if len(k) >= 64 && k[:64] == digest {
			removed = true
			continue
		}
		entries[k] = v
	}
	if !removed {
		return
	}
	// Reject any in-flight bulk response based on the older authorization.
	c.generation++
	if c.replaceLocked(entries) != nil {
		c.entries = entries
	}
}

// Refresh fetches a complete set, so a revoked token disappears even if nobody downloads it.
func (b *Bot) refreshSubscriptionCache(ctx context.Context) error {
	if b.subscriptionCache == nil {
		return nil
	}
	c := b.subscriptionCache
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.mu.Lock()
	generation := c.generation
	c.revokedDuringRefresh = make(map[string]struct{})
	c.revocationOverflow = false
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.revokedDuringRefresh = nil; c.revocationOverflow = false; c.mu.Unlock() }()
	req, err := http.NewRequestWithContext(ctx, "GET", b.adminAPIURL+"/v1/subscriptions/cache", nil)
	if err != nil {
		return errors.New("subscription cache upstream unavailable")
	}
	req.Header.Set("Authorization", "Bearer "+b.adminAPIToken)
	response, err := (&http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return errors.New("subscription cache upstream unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != 200 {
		return fmt.Errorf("subscription cache upstream status %d", response.StatusCode)
	}
	var snapshot subscriptionCacheSnapshot
	data, readErr := io.ReadAll(io.LimitReader(response.Body, maxSubscriptionCacheSize+1))
	if readErr != nil || len(data) > maxSubscriptionCacheSize {
		return errors.New("subscription cache response too large")
	}
	if err = json.Unmarshal(data, &snapshot); err != nil || snapshot.Version != 1 {
		return errors.New("invalid subscription cache response")
	}
	now := time.Now()
	for _, entry := range snapshot.Entries {
		if !validSubscriptionTime(entry.ConfirmedAt, now) {
			return errors.New("subscription cache upstream stale")
		}
	}
	b.subscriptionCache.mu.Lock()
	defer b.subscriptionCache.mu.Unlock()
	if generation != b.subscriptionCache.generation {
		return errors.New("subscription cache refresh superseded by revocation")
	}
	if b.subscriptionCache.revocationOverflow {
		return errors.New("subscription cache refresh exceeded revocation bound")
	}
	for key := range snapshot.Entries {
		if len(key) >= 64 {
			if _, revoked := b.subscriptionCache.revokedDuringRefresh[key[:64]]; revoked {
				delete(snapshot.Entries, key)
			}
		}
	}
	previousPolicy := c.happDefaultJSON
	c.happDefaultJSON = snapshot.HappDefaultJSON
	if err := c.replaceLocked(snapshot.Entries); err != nil {
		c.happDefaultJSON = previousPolicy
		return err
	}
	return nil
}
func (b *Bot) StartSubscriptionCacheWorker(ctx context.Context) {
	if b.subscriptionCache == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			c, cancel := context.WithTimeout(ctx, 15*time.Second)
			err := b.refreshSubscriptionCache(c)
			cancel()
			if err != nil && ctx.Err() == nil {
				b.log.Warn("subscription cache refresh unavailable")
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (b *Bot) subscriptionFallbackKey(token string, r *http.Request) (string, error) {
	enabled := false
	if b.subscriptionCache != nil {
		b.subscriptionCache.mu.RLock()
		enabled = b.subscriptionCache.happDefaultJSON
		b.subscriptionCache.mu.RUnlock()
	}
	format, err := config.ResolveSubscriptionFormat(r.URL.Query().Get("format"), r.URL.Query().Get("transport"), r.UserAgent(), enabled)
	if err != nil {
		return "", err
	}
	return subscriptionCacheKey(token, config.SubscriptionCacheQuery(format, r.URL.Query().Get("transport"))), nil
}

// Select policy and body from the same generation; a concurrent refresh cannot
// combine an old default with a new representation.
func (b *Bot) serveSubscriptionFallback(w http.ResponseWriter, _ string, token string, r *http.Request) bool {
	if r.URL.Query().Get("preview") != "" || b.subscriptionCache == nil {
		return false
	}
	c := b.subscriptionCache
	c.mu.RLock()
	format, err := config.ResolveSubscriptionFormat(r.URL.Query().Get("format"), r.URL.Query().Get("transport"), r.UserAgent(), c.happDefaultJSON)
	if err != nil {
		c.mu.RUnlock()
		return false
	}
	key := subscriptionCacheKey(token, config.SubscriptionCacheQuery(format, r.URL.Query().Get("transport")))
	v, ok := c.entries[key]
	if !ok && !c.happDefaultJSON {
		// Old URI-only snapshots remain readable until their original expiry.
		query := url.Values{"format": r.URL.Query()["format"], "transport": r.URL.Query()["transport"]}.Encode()
		v, ok = c.entries[subscriptionCacheKey(token, query)]
	}
	valid := ok && validSubscriptionTime(v.ConfirmedAt, time.Now())
	c.mu.RUnlock()
	if !valid {
		return false
	}
	for key, value := range v.Headers {
		w.Header().Set(key, value)
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "User-Agent")
	w.Header().Set("X-Ultra-State", "cached")
	b.setSubscriptionSupportURL(w.Header())
	subscriptionmeta.MarkStale(w.Header(), v.ConfirmedAt)
	_, _ = w.Write(v.Body)
	return true
}
