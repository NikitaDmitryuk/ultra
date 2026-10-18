package deployansible

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"time"
)

var errRecoveryFenced = errors.New("recovery_fenced")

// RecoveryAnchor is provisioned separately in recovery-anchor.json, in the
// controller's private lock directory. Requests never supply verification keys.
// Removing or replacing this anchor while a journal exists fails closed.
// This protocol only fences execution; it provides no provider/rebuild executor.
// NOT REIMAGE-CAPABLE: this local anchor/journal would be destroyed by controller
// reimage. Independent authenticated export/restore and collector/provider
// execution, DB-preserving startup, and wrapper retirement are not implemented.
// No response from these APIs authorizes any provider or database mutation.
// Import closes admissions only. Drain/completion are disabled: the Go OFD lock
// is not inherited by controller/Ansible children and cannot prove quiescence.
type RecoveryAnchor struct {
	Version   int             `json:"version"`
	SignerID  string          `json:"signer_id"`
	PublicKey []byte          `json:"public_key"`
	Primary   RecoveryPrimary `json:"primary"`
}

type RecoveryPrimary struct {
	Provider         string `json:"provider"`
	AccountID        string `json:"account_id"`
	InstanceID       string `json:"instance_id"`
	SystemIdentifier string `json:"system_identifier"`
	DatabaseOID      string `json:"database_oid"`
}

type RecoveryTarget struct {
	Provider   string `json:"provider"`
	AccountID  string `json:"account_id"`
	InstanceID string `json:"instance_id"`
	Role       string `json:"role"`
}

// RecoveryFenceRequest binds independent evidence to the exact manual journal
// and predecessor chain, rather than manufacturing missing activate receipts.
// Hashes identify evidence; this slice does not collect or certify that evidence.
type RecoveryFenceRequest struct {
	Version             int              `json:"version"`
	SignerID            string           `json:"signer_id"`
	RecoveryID          string           `json:"recovery_id"`
	Nonce               string           `json:"nonce"`
	IssuedAt            int64            `json:"issued_at"`
	ExpiresAt           int64            `json:"expires_at"`
	ManualJournalSHA256 string           `json:"manual_journal_sha256"`
	PredecessorSHA256   []string         `json:"predecessor_sha256"`
	CandidateSHA256     string           `json:"candidate_sha256"`
	FleetSHA256         string           `json:"fleet_sha256"`
	Primary             RecoveryPrimary  `json:"primary"`
	Targets             []RecoveryTarget `json:"targets"`
}

type SignedRecoveryFenceRequest struct {
	Request   RecoveryFenceRequest `json:"request"`
	Signature []byte               `json:"signature"`
}

// RecoveryFenceCompletion is an independent trusted executor's completion, not
// an operator assertion or a preflight receipt. Its signature binds the entire
// original request. Its release path is reserved and currently disabled until
// independent controller, descendant, and remote-worker quiescence is enforced.
// There is deliberately no unsigned release or TTL release.
type RecoveryFenceCompletion struct {
	Version                   int    `json:"version"`
	SignerID                  string `json:"signer_id"`
	RequestSHA256             string `json:"request_sha256"`
	Nonce                     string `json:"nonce"`
	CompletedAt               int64  `json:"completed_at"`
	ExpiresAt                 int64  `json:"expires_at"`
	TargetOutcomesSHA256      string `json:"target_outcomes_sha256"`
	PrimaryVerificationSHA256 string `json:"primary_verification_sha256"`
	BackupReceiptSHA256       string `json:"backup_receipt_sha256"`
	TunnelEscrowSHA256        string `json:"tunnel_escrow_sha256"`
	ControllerHandoffSHA256   string `json:"controller_handoff_sha256"`
}

type SignedRecoveryFenceCompletion struct {
	Completion RecoveryFenceCompletion `json:"completion"`
	Signature  []byte                  `json:"signature"`
}

type recoveryFenceJournal struct {
	Version       int                            `json:"version"`
	AnchorSHA256  string                         `json:"anchor_sha256"`
	Request       SignedRecoveryFenceRequest     `json:"request"`
	RequestSHA256 string                         `json:"request_sha256"`
	Phase         string                         `json:"phase"`
	Completion    *SignedRecoveryFenceCompletion `json:"completion,omitempty"`
	UsedNonces    []string                       `json:"used_nonces"`
}

// RecoveryFenceSigningBytes and RecoveryCompletionSigningBytes define the
// versioned, domain-separated signing format. Only public data is serialized.
func RecoveryFenceSigningBytes(r RecoveryFenceRequest) ([]byte, error) {
	raw, err := json.Marshal(r)
	return append([]byte("ultra/recovery-fence/request/v1\n"), raw...), err
}
func RecoveryCompletionSigningBytes(c RecoveryFenceCompletion) ([]byte, error) {
	raw, err := json.Marshal(c)
	return append([]byte("ultra/recovery-fence/completion/v1\n"), raw...), err
}
func recoveryHash(raw []byte) string {
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func recoveryDigest(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && len(raw) == 32 && hex.EncodeToString(raw) == s
}
func recoveryPrimaryValid(p RecoveryPrimary) bool {
	return p.Provider != "" && p.AccountID != "" && p.InstanceID != "" && p.SystemIdentifier != "" && p.DatabaseOID != ""
}
func readRecoveryJSON(path string, value any) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !ownedByProcess(info) || info.Size() > 1<<20 {
		return nil, errRecoveryFenced
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errRecoveryFenced
	}
	return raw, nil
}
func loadRecoveryAnchor(directory string) (RecoveryAnchor, string, error) {
	var a RecoveryAnchor
	raw, err := readRecoveryJSON(filepath.Join(directory, "recovery-anchor.json"), &a)
	if err != nil {
		return a, "", err
	}
	if a.Version != 1 || a.SignerID == "" || len(a.PublicKey) != ed25519.PublicKeySize || !recoveryPrimaryValid(a.Primary) {
		return a, "", errRecoveryFenced
	}
	return a, recoveryHash(raw), nil
}
func validateRecoveryRequest(a RecoveryAnchor, s SignedRecoveryFenceRequest, live bool) (string, error) {
	r := s.Request
	raw, err := RecoveryFenceSigningBytes(r)
	if err != nil || r.Version != 1 || r.SignerID != a.SignerID || !jobID.MatchString(r.RecoveryID) ||
		len(r.Nonce) < 32 || len(r.Nonce) > 256 || r.IssuedAt <= 0 || r.ExpiresAt <= r.IssuedAt ||
		r.PredecessorSHA256 == nil || !recoveryDigest(r.ManualJournalSHA256) || !recoveryDigest(r.CandidateSHA256) ||
		!recoveryDigest(r.FleetSHA256) || !reflect.DeepEqual(r.Primary, a.Primary) || len(r.Targets) == 0 ||
		!ed25519.Verify(a.PublicKey, raw, s.Signature) {
		return "", errors.New("invalid_recovery_request")
	}
	if live && (r.IssuedAt > time.Now().Unix() || r.ExpiresAt <= time.Now().Unix()) {
		return "", errors.New("expired_recovery_request")
	}
	seen := map[string]bool{r.ManualJournalSHA256: true}
	for _, hash := range r.PredecessorSHA256 {
		if !recoveryDigest(hash) || seen[hash] {
			return "", errors.New("invalid_recovery_predecessors")
		}
		seen[hash] = true
	}
	targets := make(map[string]bool)
	for _, t := range r.Targets {
		identity, _ := json.Marshal([]string{t.Provider, t.AccountID, t.InstanceID})
		if t.Provider == "" || t.AccountID == "" || t.InstanceID == "" ||
			(t.Role != "bridge" && t.Role != "exit") || targets[string(identity)] ||
			(t.Provider == r.Primary.Provider && t.AccountID == r.Primary.AccountID && t.InstanceID == r.Primary.InstanceID) {
			return "", errors.New("protected_recovery_scope")
		}
		targets[string(identity)] = true
	}
	return recoveryHash(raw), nil
}
func validateRecoveryCompletion(a RecoveryAnchor, j *recoveryFenceJournal, s SignedRecoveryFenceCompletion, live bool) error {
	c := s.Completion
	raw, err := RecoveryCompletionSigningBytes(c)
	if err != nil || c.Version != 1 || c.SignerID != a.SignerID || c.RequestSHA256 != j.RequestSHA256 ||
		c.Nonce != j.Request.Request.Nonce || c.CompletedAt < j.Request.Request.IssuedAt || c.ExpiresAt <= c.CompletedAt ||
		!recoveryDigest(c.TargetOutcomesSHA256) || !recoveryDigest(c.PrimaryVerificationSHA256) ||
		!recoveryDigest(c.BackupReceiptSHA256) || !recoveryDigest(c.TunnelEscrowSHA256) || !recoveryDigest(c.ControllerHandoffSHA256) ||
		!ed25519.Verify(a.PublicKey, raw, s.Signature) {
		return errors.New("invalid_recovery_completion")
	}
	if live && (c.CompletedAt > time.Now().Unix() || c.ExpiresAt <= time.Now().Unix()) {
		return errors.New("expired_recovery_completion")
	}
	return nil
}
func loadRecoveryFence(directory string) (*recoveryFenceJournal, RecoveryAnchor, error) {
	var j recoveryFenceJournal
	_, err := readRecoveryJSON(filepath.Join(directory, "recovery-fence.json"), &j)
	if os.IsNotExist(err) {
		return nil, RecoveryAnchor{}, nil
	}
	if err != nil {
		return nil, RecoveryAnchor{}, errRecoveryFenced
	}
	a, hash, err := loadRecoveryAnchor(directory)
	if err != nil || j.Version != 1 || hash != j.AnchorSHA256 {
		return nil, a, errRecoveryFenced
	}
	requestHash, err := validateRecoveryRequest(a, j.Request, false)
	if err != nil || requestHash != j.RequestSHA256 || (j.Phase != "draining" && j.Phase != "drained") {
		return nil, a, errRecoveryFenced
	}
	seen := make(map[string]bool)
	for _, nonce := range j.UsedNonces {
		if len(nonce) < 32 || seen[nonce] {
			return nil, a, errRecoveryFenced
		}
		seen[nonce] = true
	}
	if !seen[j.Request.Request.Nonce] {
		return nil, a, errRecoveryFenced
	}
	// A completed journal from the unfinished protocol cannot establish worker
	// quiescence. Reject it above even if it contains a valid signature.
	if j.Completion != nil {
		return nil, a, errRecoveryFenced
	}
	return &j, a, nil
}

// admission serializes each check-plus-lock/stage admission against the durable
// import. It is short lived; neither this lock nor infrastructure.lock proves
// that orphaned controllers/Ansible/remote workers have stopped.
func recoveryAdmission(directory string) (func(), error) {
	// Preserve the unprovisioned path, including its filesystem behavior.
	_, aerr := os.Lstat(filepath.Join(directory, "recovery-anchor.json"))
	_, jerr := os.Lstat(filepath.Join(directory, "recovery-fence.json"))
	if os.IsNotExist(aerr) && os.IsNotExist(jerr) {
		return func() {}, nil
	}
	unlock, err := recoveryAdmissionLock(directory, false)
	if err != nil {
		return nil, errRecoveryFenced
	}
	_, _, err = loadRecoveryAnchor(directory)
	if err == nil {
		var j *recoveryFenceJournal
		j, _, err = loadRecoveryFence(directory)
		if err == nil && j != nil {
			err = errRecoveryFenced
		}
	}
	if err != nil {
		unlock()
		return nil, errRecoveryFenced
	}
	return unlock, nil
}
func recoveryAdmissionLock(directory string, exclusive bool) (func(), error) {
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 || !ownedByProcess(info) {
		return nil, errRecoveryFenced
	}
	path := filepath.Join(directory, "recovery-admission.lock")
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err = f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || !ownedByProcess(info) {
		_ = f.Close()
		return nil, errRecoveryFenced
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if err = syscall.Flock(fd, mode|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
func (g *lifecycleGate) saveRecoveryFence(j *recoveryFenceJournal) error {
	raw, err := json.Marshal(j)
	if err != nil {
		return err
	}
	_, err = g.savePrivateJSON("recovery-fence.json", raw)
	return err
}

// recoveryQuiescenceBlocker drops only the broker's retained descriptor. An
// external holder proves execution may still exist, but a free lock proves
// nothing about orphaned controllers, independently sessioned Ansible children,
// or remote workers. Until an independent collector closes that gap, this
// function NEVER returns nil and the durable fence remains draining.
func (g *lifecycleGate) recoveryQuiescenceBlocker() error {
	if g.lock != nil {
		_ = g.lock.Close()
		g.lock = nil
	}
	lock, err := controllerLock(filepath.Join(g.directory, "infrastructure.lock"))
	if err != nil {
		return errors.New("recovery_drain_pending")
	}
	_ = lock.Close()
	return errors.New("recovery_independent_quiescence_required")
}
func (g *lifecycleGate) importRecoveryFence(s SignedRecoveryFenceRequest) Response {
	g.mu.Lock()
	defer g.mu.Unlock()
	unlock, err := recoveryAdmissionLock(g.directory, true)
	if err != nil {
		return Response{Code: "recovery_admission_busy"}
	}
	defer unlock()
	a, anchorHash, err := loadRecoveryAnchor(g.directory)
	if err != nil {
		return Response{Code: "recovery_anchor_required"}
	}
	hash, err := validateRecoveryRequest(a, s, true)
	if err != nil {
		return Response{Code: err.Error()}
	}
	previous, _, err := loadRecoveryFence(g.directory)
	if err != nil {
		return Response{Code: "recovery_fenced"}
	}
	if previous != nil {
		if previous.RequestSHA256 != hash {
			return Response{Code: "recovery_fenced"}
		}
		return Response{Code: g.recoveryQuiescenceBlocker().Error()}
	}
	j := &recoveryFenceJournal{Version: 1, AnchorSHA256: anchorHash, Request: s, RequestSHA256: hash, Phase: "draining", UsedNonces: []string{s.Request.Nonce}}
	// Persist closure before closing our OFD or testing external holder drain.
	if err = g.saveRecoveryFence(j); err != nil {
		return Response{Code: "recovery_persistence_failed"}
	}
	return Response{Code: g.recoveryQuiescenceBlocker().Error()}
}
func (g *lifecycleGate) completeRecoveryFence(s SignedRecoveryFenceCompletion) Response {
	g.mu.Lock()
	defer g.mu.Unlock()
	unlock, err := recoveryAdmissionLock(g.directory, true)
	if err != nil {
		return Response{Code: "recovery_admission_busy"}
	}
	defer unlock()
	j, a, err := loadRecoveryFence(g.directory)
	if err != nil || j == nil {
		return Response{Code: "recovery_fenced"}
	}
	if err = validateRecoveryCompletion(a, j, s, true); err != nil {
		return Response{Code: err.Error()}
	}
	// A signature over evidence hashes cannot replace an implemented verifier
	// of execution quiescence. Do not release even a correctly signed completion.
	return Response{Code: "recovery_completion_unsupported"}
}

func (c Client) ImportRecoveryFence(ctx context.Context, request SignedRecoveryFenceRequest) error {
	_, err := c.exchange(ctx, Message{Action: "recovery-fence-import", RecoveryFence: &request})
	if err != nil {
		return err
	}
	return errors.New("recovery_independent_quiescence_required")
}
func (c Client) CompleteRecoveryFence(ctx context.Context, completion SignedRecoveryFenceCompletion) error {
	_, err := c.exchange(ctx, Message{Action: "recovery-fence-complete", RecoveryCompletion: &completion})
	if err != nil {
		return err
	}
	return errors.New("recovery_completion_unsupported")
}

// Execute also has direct callers. Under a provisioned anchor it must either
// participate in the existing worker lease or hold its own infrastructure lock.
func recoveryExecutionAdmission(ctx context.Context, directory string) (func(), error) {
	// Avoid changing direct Execute's behavior without provisioned trust/state.
	_, aerr := os.Lstat(filepath.Join(directory, "recovery-anchor.json"))
	_, jerr := os.Lstat(filepath.Join(directory, "recovery-fence.json"))
	if os.IsNotExist(aerr) && os.IsNotExist(jerr) {
		return func() {}, nil
	}
	lease, leased := ctx.Value(operationLeaseKey{}).(*operationLease)
	if leased {
		lease.run.Lock()
	}
	admission, err := recoveryAdmission(directory)
	if err != nil {
		if leased {
			lease.run.Unlock()
		}
		return nil, err
	}
	defer admission()
	if leased {
		if !lease.active.Load() || lease.directory != directory {
			lease.run.Unlock()
			return nil, errRecoveryFenced
		}
		return func() { lease.run.Unlock() }, nil
	}
	lock, err := controllerLock(filepath.Join(directory, "infrastructure.lock"))
	if err != nil {
		return nil, err
	}
	return func() { _ = lock.Close() }, nil
}
