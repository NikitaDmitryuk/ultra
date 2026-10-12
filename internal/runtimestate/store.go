// Package runtimestate owns the relay's single-writer, crash-consistent local state.
// PostgreSQL remains authoritative for access; this store bounds disconnected use.
package runtimestate

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	bolt "go.etcd.io/bbolt"
)

const ReservationChunk int64 = 256 * 1024
const SnapshotTTL = 24 * time.Hour
const MaxPendingBytes = 128 * 1024 * 1024

var ErrQuota = errors.New("runtime quota exhausted or unavailable")
var ErrExpired = errors.New("runtime authorization expired")
var ErrNoSnapshot = errors.New("runtime snapshot unavailable")
var ErrJournalFull = errors.New("runtime traffic journal full")

type Snapshot struct {
	Revision    uint64          `json:"revision"`
	ConfirmedAt time.Time       `json:"confirmed_at"`
	Payload     json.RawMessage `json:"payload"`
}
type QuotaLimit struct {
	AccountID      string    `json:"account_id"`
	ExitID         string    `json:"exit_id"`
	Period         string    `json:"period"`
	LimitBytes     int64     `json:"limit_bytes"`
	UsedBytes      int64     `json:"used_bytes"`
	ExpiresAt      time.Time `json:"expires_at"`
	EmergencyAfter time.Time `json:"emergency_after,omitempty"`
	EmergencyBytes int64     `json:"emergency_bytes,omitempty"`
}
type Sample struct {
	AccountID        string `json:"account_id"`
	ExitID           string `json:"exit_id"`
	ExitTag          string `json:"exit_tag"`
	Period           string `json:"period"`
	UplinkBytes      int64  `json:"uplink_bytes"`
	DownlinkBytes    int64  `json:"downlink_bytes"`
	ChargeTotalBytes int64  `json:"charge_total_bytes"`
}
type TrafficBatch struct {
	Version     int       `json:"version"`
	NodeID      string    `json:"node_id"`
	BatchID     string    `json:"batch_id"`
	CollectedAt time.Time `json:"collected_at"`
	Samples     []Sample  `json:"samples"`
}
type quotaState struct {
	QuotaLimit
	Spent             int64  `json:"spent"`
	EmergencyBaseline *int64 `json:"emergency_baseline,omitempty"`
}
type Store struct {
	mu sync.Mutex
	db *bolt.DB
	// Credits are already durably charged, shared across every connection/direction.
	// On restart they are intentionally lost, never returned to the allowance.
	credits map[string]int64
	now     func() time.Time
}

var metaBucket = []byte("meta")
var quotaBucket = []byte("quotas")
var batchBucket = []byte("batches")
var chargeWatermarkBucket = []byte("charge_watermarks")
var batchInputBucket = []byte("batch_inputs")
var emergencyBaselineBucket = []byte("emergency_baselines")

func Open(path string) (*Store, error) {
	// bbolt initializes a zero-length file as a brand-new database. An existing
	// truncated journal must never be mistaken for first boot and refund charges.
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return nil, errors.New("existing runtime state is empty or not a regular database")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, credits: map[string]int64{}, now: time.Now}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{metaBucket, quotaBucket, batchBucket, chargeWatermarkBucket, batchInputBucket, emergencyBaselineBucket} {
			if _, e := tx.CreateBucketIfNotExists(b); e != nil {
				return e
			}
		}
		// A compatible older binary acknowledges batches without knowing this index.
		// Reclaim its orphan digests while retaining cumulative watermarks.
		inputs := tx.Bucket(batchInputBucket)
		var orphaned [][]byte
		if err := inputs.ForEach(func(k, _ []byte) error {
			if tx.Bucket(batchBucket).Get(k) == nil {
				orphaned = append(orphaned, bytes.Clone(k))
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range orphaned {
			if err := inputs.Delete(k); err != nil {
				return err
			}
		}
		b := tx.Bucket(metaBucket)
		if b.Get([]byte("node_id")) == nil {
			if err := b.Put([]byte("node_id"), []byte(uuid.NewString())); err != nil {
				return err
			}
		}
		var size int64
		if err := tx.Bucket(batchBucket).ForEach(func(_, v []byte) error { size += int64(len(v)); return nil }); err != nil {
			return err
		}
		return putJournalBytes(tx, size)
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { s.mu.Lock(); defer s.mu.Unlock(); return s.db.Close() }
func (s *Store) NodeID() string {
	var id string
	_ = s.db.View(func(tx *bolt.Tx) error { id = string(tx.Bucket(metaBucket).Get([]byte("node_id"))); return nil })
	return id
}
func quotaKey(account, exit, period string) string { return period + "/" + exit + "/" + account }
func (s *Store) SaveSnapshot(snapshot Snapshot, limits []QuotaLimit) error {
	if len(snapshot.Payload) == 0 || !json.Valid(snapshot.Payload) || snapshot.ConfirmedAt.IsZero() {
		return errors.New("invalid runtime snapshot")
	}
	if snapshot.ConfirmedAt.After(s.now().Add(time.Minute)) {
		return errors.New("snapshot timestamp is in the future")
	}
	raw, e := json.Marshal(snapshot)
	if e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		if old := tx.Bucket(metaBucket).Get([]byte("snapshot")); old != nil {
			var v Snapshot
			if e := json.Unmarshal(old, &v); e != nil {
				return e
			}
			if snapshot.ConfirmedAt.Before(v.ConfirmedAt) {
				return errors.New("snapshot confirmation regressed")
			}
		}
		if e := setLimits(tx, limits); e != nil {
			return e
		}
		return tx.Bucket(metaBucket).Put([]byte("snapshot"), raw)
	})
}
func (s *Store) LoadSnapshot() (Snapshot, error) {
	var snap Snapshot
	e := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(metaBucket).Get([]byte("snapshot"))
		if raw == nil {
			return ErrNoSnapshot
		}
		return json.Unmarshal(raw, &snap)
	})
	return snap, e
}
func (s *Store) SetQuotaLimits(limits []QuotaLimit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error { return setLimits(tx, limits) })
}
func setLimits(tx *bolt.Tx, limits []QuotaLimit) error {
	b := tx.Bucket(quotaBucket)
	// Expire removed entries; never mutate a bucket while its cursor is traversing.
	prior := map[string]quotaState{}
	if err := b.ForEach(func(k, v []byte) error {
		var q quotaState
		if err := json.Unmarshal(v, &q); err != nil {
			return err
		}
		prior[string(k)] = q
		return nil
	}); err != nil {
		return err
	}
	for k, q := range prior {
		// Preserve the original outage baseline before replacing an observation.
		// A failed candidate may restore this observation after its quota row changed.
		if q.AccountID == "" && !q.EmergencyAfter.IsZero() && q.EmergencyBaseline != nil {
			var value [8]byte
			binary.BigEndian.PutUint64(value[:], uint64(*q.EmergencyBaseline))
			if err := tx.Bucket(emergencyBaselineBucket).Put([]byte(emergencyKey(q.QuotaLimit)), value[:]); err != nil {
				return err
			}
		}
		q.ExpiresAt = time.Time{}
		raw, err := json.Marshal(q)
		if err != nil {
			return err
		}
		if err = b.Put([]byte(k), raw); err != nil {
			return err
		}
	}
	for _, l := range limits {
		if l.ExitID == "" || l.Period == "" || l.LimitBytes < 0 || l.UsedBytes < 0 {
			return errors.New("invalid runtime quota")
		}
		key := []byte(quotaKey(l.AccountID, l.ExitID, l.Period))
		q := quotaState{QuotaLimit: l, Spent: l.UsedBytes}
		if raw := b.Get(key); raw != nil {
			var old quotaState
			if e := json.Unmarshal(raw, &old); e != nil {
				return e
			}
			q.Spent = max(q.Spent, old.Spent)
			if q.EmergencyAfter.Equal(old.EmergencyAfter) {
				q.EmergencyBaseline = old.EmergencyBaseline
			}
		}
		if q.AccountID == "" && !q.EmergencyAfter.IsZero() && q.EmergencyBaseline == nil {
			if value := tx.Bucket(emergencyBaselineBucket).Get([]byte(emergencyKey(l))); value != nil {
				if len(value) != 8 || binary.BigEndian.Uint64(value) > uint64(^uint64(0)>>1) {
					return errors.New("invalid emergency baseline")
				}
				baseline := int64(binary.BigEndian.Uint64(value))
				q.EmergencyBaseline = &baseline
			}
		}
		raw, _ := json.Marshal(q)
		if e := b.Put(key, raw); e != nil {
			return e
		}
	}
	return nil
}
func emergencyKey(q QuotaLimit) string {
	return quotaKey("", q.ExitID, q.Period) + "/" + q.EmergencyAfter.UTC().Format(time.RFC3339Nano)
}
func loadQuota(tx *bolt.Tx, key string, now time.Time) (quotaState, error) {
	var q quotaState
	raw := tx.Bucket(quotaBucket).Get([]byte(key))
	if raw == nil {
		return q, ErrQuota
	}
	if err := json.Unmarshal(raw, &q); err != nil {
		return q, err
	}
	if q.ExpiresAt.IsZero() || !now.Before(q.ExpiresAt) {
		return q, ErrExpired
	}
	return q, nil
}
func (s *Store) remaining(tx *bolt.Tx, account, exit string, now time.Time) (int64, quotaState, quotaState, error) {
	raw := tx.Bucket(metaBucket).Get([]byte("snapshot"))
	if raw == nil {
		return 0, quotaState{}, quotaState{}, ErrNoSnapshot
	}
	var snap Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return 0, quotaState{}, quotaState{}, err
	}
	if now.Before(snap.ConfirmedAt.Add(-time.Minute)) || !now.Before(snap.ConfirmedAt.Add(SnapshotTTL)) {
		return 0, quotaState{}, quotaState{}, ErrExpired
	}
	period := now.UTC().Format("2006-01")
	key := quotaKey(account, exit, period)
	u, e := loadQuota(tx, key, now)
	if e != nil {
		return 0, u, quotaState{}, e
	}
	g, e := loadQuota(tx, quotaKey("", exit, period), now)
	if e != nil {
		return 0, u, g, e
	}
	credit := s.credits[key]
	return max(0, min(u.LimitBytes-u.Spent, quotaAvailable(g, now))+credit), u, g, nil
}
func (s *Store) Remaining(account, exit string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var left int64
	e := s.db.View(func(tx *bolt.Tx) error {
		var e error
		left, _, _, e = s.remaining(tx, account, exit, s.now())
		return e
	})
	return left, e
}

// Reserve authorizes up to want bytes, reserving durable chunks before transmission.
// Partial results are allowed at a quota boundary; callers must never transmit more.
func (s *Store) Reserve(account, exit string, want int64) (int64, error) {
	if account == "" || exit == "" || want < 0 {
		return 0, ErrQuota
	}
	if want == 0 {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	key := quotaKey(account, exit, now.UTC().Format("2006-01"))
	var grant, reserved int64
	// Spending an already synced reservation requires no disk commit. The read
	// still validates the current lease, quotas and journal capacity under s.mu.
	e := s.db.View(func(tx *bolt.Tx) error {
		left, _, _, err := s.remaining(tx, account, exit, now)
		if err != nil {
			return err
		}
		if left <= 0 {
			return ErrQuota
		}
		if journalBytes(tx) >= MaxPendingBytes-1024*1024 {
			return ErrJournalFull
		}
		grant = min(want, ReservationChunk, left)
		return nil
	})
	if e != nil {
		return 0, e
	}
	if s.credits[key] >= grant {
		s.credits[key] -= grant
		return grant, nil
	}
	e = s.db.Update(func(tx *bolt.Tx) error {
		left, u, g, e := s.remaining(tx, account, exit, now)
		if e != nil {
			return e
		}
		if left <= 0 {
			return ErrQuota
		}
		credit := s.credits[key]
		grant = min(want, ReservationChunk, left)
		if journalBytes(tx) >= MaxPendingBytes-1024*1024 {
			return ErrJournalFull
		}
		if credit < grant {
			reserve := min(ReservationChunk-credit, max(0, min(u.LimitBytes-u.Spent, quotaAvailable(g, now))))
			if reserve == 0 {
				grant = min(grant, credit)
			} else {
				reserved = reserve
				if !g.EmergencyAfter.IsZero() && !now.Before(g.EmergencyAfter) && g.EmergencyBaseline == nil {
					v := g.Spent
					g.EmergencyBaseline = &v
				}
				u.Spent += reserve
				g.Spent += reserve
				for _, q := range []quotaState{u, g} {
					raw, _ := json.Marshal(q)
					if e := tx.Bucket(quotaBucket).Put([]byte(quotaKey(q.AccountID, q.ExitID, q.Period)), raw); e != nil {
						return e
					}
				}
				credit += reserve
			}
			grant = min(grant, credit)
		}
		if grant <= 0 {
			return ErrQuota
		}
		return nil
	})
	if e != nil {
		return 0, e
	}
	s.credits[key] += reserved - grant
	return grant, nil
}

// AppendBatch queues only measured deltas or cumulative reservations not already
// queued. The watermark shares the transaction with the immutable journal entry.
func (s *Store) AppendBatch(batch TrafficBatch) error { return s.appendBatch(batch, false) }

// AppendBatchFull reconciles an older PostgreSQL backup after startup/recovery.
func (s *Store) AppendBatchFull(batch TrafficBatch) error { return s.appendBatch(batch, true) }
func (s *Store) appendBatch(batch TrafficBatch, full bool) error {
	if batch.BatchID == "" || batch.NodeID == "" || batch.CollectedAt.IsZero() {
		return errors.New("invalid traffic batch")
	}
	batch.Version = 1
	batch.Samples = append([]Sample(nil), batch.Samples...)
	for i := range batch.Samples {
		if batch.Samples[i].Period == "" {
			batch.Samples[i].Period = batch.CollectedAt.UTC().Format("2006-01")
		}
	}
	sortTrafficSamples(batch.Samples)
	input, err := json.Marshal(struct {
		Full  bool
		Batch TrafficBatch
	}{full, batch})
	if err != nil {
		return err
	}
	digest := sha256.Sum256(input)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(batchBucket)
		key := []byte(batch.BatchID)
		inputs := tx.Bucket(batchInputBucket)
		if bucket.Get(key) != nil {
			if bytes.Equal(inputs.Get(key), digest[:]) {
				return nil
			}
			return errors.New("traffic batch identity conflict")
		}
		charges := map[string]quotaState{}
		watermarks := tx.Bucket(chargeWatermarkBucket)
		if err := tx.Bucket(quotaBucket).ForEach(func(_, v []byte) error {
			var q quotaState
			if err := json.Unmarshal(v, &q); err != nil {
				return err
			}
			if q.AccountID != "" {
				charges[quotaKey(q.AccountID, q.ExitID, q.Period)] = q
			}
			return nil
		}); err != nil {
			return err
		}
		actual := batch.Samples
		batch.Samples = nil
		queued := map[string]int64{}
		for _, sample := range actual {
			if sample.UplinkBytes == 0 && sample.DownlinkBytes == 0 && sample.ChargeTotalBytes == 0 {
				continue
			}
			k := quotaKey(sample.AccountID, sample.ExitID, sample.Period)
			if q, ok := charges[k]; ok {
				sample.ChargeTotalBytes = q.Spent
				queued[k] = q.Spent
				delete(charges, k)
			}
			batch.Samples = append(batch.Samples, sample)
		}
		for k, q := range charges {
			v := watermarks.Get([]byte(k))
			var last int64
			if len(v) == 8 {
				last = int64(binary.BigEndian.Uint64(v))
			}
			if q.Spent > 0 && (full || q.Spent > last) {
				batch.Samples = append(batch.Samples, Sample{AccountID: q.AccountID, ExitID: q.ExitID, ExitTag: "to-exit-" + q.ExitID, Period: q.Period, ChargeTotalBytes: q.Spent})
				queued[k] = q.Spent
			}
		}
		if len(batch.Samples) == 0 {
			return nil
		}
		sortTrafficSamples(batch.Samples)
		raw, err := json.Marshal(batch)
		if err != nil {
			return err
		}
		size := journalBytes(tx)
		if size+int64(len(raw)) > MaxPendingBytes {
			return ErrJournalFull
		}
		if err = bucket.Put(key, raw); err != nil {
			return err
		}
		if err = inputs.Put(key, digest[:]); err != nil {
			return err
		}
		for k, total := range queued {
			var v [8]byte
			binary.BigEndian.PutUint64(v[:], uint64(total))
			if err = watermarks.Put([]byte(k), v[:]); err != nil {
				return err
			}
		}
		return putJournalBytes(tx, size+int64(len(raw)))
	})
}
func sortTrafficSamples(samples []Sample) {
	sort.SliceStable(samples, func(i, j int) bool {
		a, b := samples[i], samples[j]
		if a.AccountID != b.AccountID {
			return a.AccountID < b.AccountID
		}
		if a.ExitID != b.ExitID {
			return a.ExitID < b.ExitID
		}
		if a.Period != b.Period {
			return a.Period < b.Period
		}
		if a.ExitTag != b.ExitTag {
			return a.ExitTag < b.ExitTag
		}
		if a.UplinkBytes != b.UplinkBytes {
			return a.UplinkBytes < b.UplinkBytes
		}
		if a.DownlinkBytes != b.DownlinkBytes {
			return a.DownlinkBytes < b.DownlinkBytes
		}
		return a.ChargeTotalBytes < b.ChargeTotalBytes
	})
}
func (s *Store) PendingBatches(limit int) ([]TrafficBatch, error) {
	out := []TrafficBatch{}
	e := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(batchBucket).Cursor()
		for k, v := c.First(); k != nil && (limit <= 0 || len(out) < limit); k, v = c.Next() {
			var b TrafficBatch
			if e := json.Unmarshal(v, &b); e != nil {
				return fmt.Errorf("decode traffic journal: %w", e)
			}
			out = append(out, b)
		}
		return nil
	})
	return out, e
}
func (s *Store) AckBatch(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(batchBucket)
		old := b.Get([]byte(id))
		n := int64(len(old))
		if err := b.Delete([]byte(id)); err != nil {
			return err
		}
		if err := tx.Bucket(batchInputBucket).Delete([]byte(id)); err != nil {
			return err
		}
		return putJournalBytes(tx, max(0, journalBytes(tx)-n))
	})
}
func (s *Store) PendingStats() (count int, bytes int64, oldest time.Time, err error) {
	err = s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(batchBucket).ForEach(func(_, v []byte) error {
			var b TrafficBatch
			if e := json.Unmarshal(v, &b); e != nil {
				return e
			}
			count++
			bytes += int64(len(v))
			if oldest.IsZero() || b.CollectedAt.Before(oldest) {
				oldest = b.CollectedAt
			}
			return nil
		})
	})
	return
}

func quotaAvailable(q quotaState, now time.Time) int64 {
	left := q.LimitBytes - q.Spent
	if !q.EmergencyAfter.IsZero() && !now.Before(q.EmergencyAfter) {
		baseline := q.Spent
		if q.EmergencyBaseline != nil {
			baseline = *q.EmergencyBaseline
		}
		left = min(left, q.EmergencyBytes-max(0, q.Spent-baseline))
	}
	return max(0, left)
}

// RestoreSnapshot is exclusively for rolling back a failed core apply. Durable
// reservations remain monotonic; rollback never refunds bytes transmitted meanwhile.
func (s *Store) RestoreSnapshot(snapshot *Snapshot, limits []QuotaLimit) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := setLimits(tx, limits); err != nil {
			return err
		}
		b := tx.Bucket(metaBucket)
		if snapshot == nil {
			return b.Delete([]byte("snapshot"))
		}
		raw, err := json.Marshal(snapshot)
		if err != nil {
			return err
		}
		return b.Put([]byte("snapshot"), raw)
	})
}
func journalBytes(tx *bolt.Tx) int64 {
	v := tx.Bucket(metaBucket).Get([]byte("journal_bytes"))
	if len(v) != 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(v))
}
func putJournalBytes(tx *bolt.Tx, n int64) error {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(n))
	return tx.Bucket(metaBucket).Put([]byte("journal_bytes"), b[:])
}

// ValidateAuthorization gates bridge-local direct traffic without charging an exit.
// At least one current account allowance must remain; the raw client never goes direct.
func (s *Store) ValidateAuthorization(account string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.View(func(tx *bolt.Tx) error {
		permitted := false
		var leaseErr error
		err := tx.Bucket(quotaBucket).ForEach(func(_, v []byte) error {
			var q quotaState
			if err := json.Unmarshal(v, &q); err != nil {
				return err
			}
			if q.AccountID != account || q.Period != s.now().UTC().Format("2006-01") {
				return nil
			}
			left, _, _, err := s.remaining(tx, account, q.ExitID, s.now())
			if err != nil {
				leaseErr = err
			} else if left > 0 {
				permitted = true
			}
			return nil
		})
		if err != nil {
			return err
		}
		if permitted {
			return nil
		}
		if leaseErr != nil {
			return leaseErr
		}
		return ErrQuota
	})
}
