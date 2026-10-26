package cloud

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/google/uuid"
)

const MaxServers = 5

var ErrLimit = errors.New("cloud server slots already reserved")
var ErrConflict = errors.New("operation cannot be changed in current state")

type Offer struct {
	ID        string    `json:"id"`
	Actor     int64     `json:"actor"`
	Region    Region    `json:"region"`
	Plan      Plan      `json:"plan"`
	Price     Cost      `json:"price"`
	ExpiresAt time.Time `json:"expires_at"`
	ReplaceID string    `json:"replace_id,omitempty"`
}
type Operation struct {
	ServesSubscriptionIngress bool      `json:"serves_subscription_ingress"`
	ErrorMessage              string    `json:"error_message,omitempty"`
	HTTPStatus                int       `json:"http_status,omitempty"`
	ReplicationState          string    `json:"replication_state,omitempty"`
	InstallAttempt            uint64    `json:"install_attempt,omitempty"`
	Reinstall                 bool      `json:"reinstall,omitempty"`
	ReinstallJobID            string    `json:"reinstall_job_id,omitempty"`
	ReinstallTarget           string    `json:"reinstall_target,omitempty"`
	RetirementTarget          string    `json:"retirement_target,omitempty"`
	ID                        string    `json:"id"`
	Offer                     Offer     `json:"offer"`
	State                     string    `json:"state"`
	Phase                     string    `json:"phase"`
	InstanceID                string    `json:"instance_id,omitempty"`
	ExitID                    string    `json:"exit_id,omitempty"`
	FirewallID                string    `json:"firewall_id,omitempty"`
	Error                     string    `json:"error,omitempty"`
	Charged                   bool      `json:"charged"`
	CreatedAt                 time.Time `json:"created_at"`
}
type Store interface {
	SaveOffer(context.Context, Offer) error
	Offer(context.Context, string) (Offer, error)
	Reserve(context.Context, Offer) (Operation, error)
	List(context.Context) ([]Operation, error)
	Get(context.Context, string) (Operation, error)
	Save(context.Context, Operation) error
	Lock(context.Context) (func(), error)
	Audit(context.Context, int64, string, string) error
	RecordEvent(context.Context, Event) error
	Events(context.Context, string) ([]Event, error)
}
type Provider interface {
	Regions(context.Context) ([]Region, error)
	Plans(context.Context) ([]Plan, error)
	Available(context.Context, string, string) (bool, error)
	Create(context.Context, CreateRequest) (Instance, error)
	Instances(context.Context) ([]Instance, error)
	Get(context.Context, string) (Instance, error)
	Delete(context.Context, string) error
}
type Provisioner interface {
	Prepare(context.Context, *Operation) (CreateRequest, error)
	Install(context.Context, *Operation, Instance) error
	Verify(context.Context, *Operation, Instance) error
	Publish(context.Context, *Operation) error
	ApplyRoute(context.Context, *Operation) error
	Unpublish(context.Context, *Operation) error
	ValidateDelete(context.Context, *Operation) error
	Cleanup(context.Context, *Operation) error
}
type Service struct {
	// LockTopology is acquired before Store.Lock, matching the admin mutation/drain order.
	// Nil is supported for standalone services and tests.
	LockTopology      func(context.Context) (func(), error)
	TopologyReady     func(context.Context) error
	IngressInstanceID string
	Log               *slog.Logger
	API               Provider
	Store             Store
	Provisioner       Provisioner
	Now               func() time.Time
}

// capacityLocker separates the short reservation gate from the worker lock.
// Stores that do not provide it retain the old locking behavior for compatibility.
type capacityLocker interface {
	LockCapacity(context.Context) (func(), error)
}

func (s *Service) lockCapacity(ctx context.Context) (func(), error) {
	if locker, ok := s.Store.(capacityLocker); ok {
		return locker.LockCapacity(ctx)
	}
	return s.Store.Lock(ctx)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}
func (s *Service) Catalog(ctx context.Context) ([]Region, []Plan, error) {
	r, e := s.API.Regions(ctx)
	if e != nil {
		return nil, nil, e
	}
	p, e := s.API.Plans(ctx)
	return r, p, e
}
func (s *Service) Quote(ctx context.Context, actor int64, region, plan, replace string) (Offer, error) {
	if actor <= 0 {
		return Offer{}, ErrConflict
	}
	if e := s.checkReplacement(ctx, replace); e != nil {
		return Offer{}, e
	}
	regions, plans, e := s.Catalog(ctx)
	if e != nil {
		return Offer{}, e
	}
	var selected Region
	for _, r := range regions {
		if r.ID == region {
			selected = r
		}
	}
	var tariff Plan
	for _, p := range plans {
		if p.ID == plan {
			tariff = p
		}
	}
	price := tariff.Price(region)
	if selected.ID == "" || tariff.ID == "" || tariff.RAM < 1024 || price.Monthly <= 0 || price.Monthly > 5 || price.Hourly <= 0 {
		return Offer{}, ErrPriceChanged
	}
	if replace != "" {
		old, e := s.Store.Get(ctx, replace)
		if e != nil || old.State != "ready" || old.InstanceID == "" {
			return Offer{}, ErrConflict
		}
	}
	available, e := s.API.Available(ctx, region, plan)
	if e != nil {
		return Offer{}, e
	}
	if !available {
		return Offer{}, APIError{Code: "region_unavailable"}
	}
	offer := Offer{
		ID:        uuid.NewString(),
		Actor:     actor,
		Region:    selected,
		Plan:      tariff,
		Price:     price,
		ExpiresAt: s.now().Add(5 * time.Minute),
		ReplaceID: replace,
	}
	return offer, s.Store.SaveOffer(ctx, offer)
}
func (s *Service) checkOffer(ctx context.Context, o Offer) error {
	if !s.now().Before(o.ExpiresAt) {
		return ErrPriceChanged
	}
	return s.checkPurchaseOffer(ctx, o)
}

// Confirmation consumes the quote lifetime. Queued, confirmed operations still
// revalidate the approved price and current availability before buying a VPS.
func (s *Service) checkPurchaseOffer(ctx context.Context, o Offer) error {
	if e := s.checkReplacement(ctx, o.ReplaceID); e != nil {
		return e
	}
	plans, e := s.API.Plans(ctx)
	if e != nil {
		return e
	}
	for _, p := range plans {
		if p.ID == o.Plan.ID {
			if p.Price(o.Region.ID) != o.Price || p.Price(o.Region.ID).Monthly > 5 {
				return ErrPriceChanged
			}
			available, e := s.API.Available(ctx, o.Region.ID, p.ID)
			if e != nil {
				return e
			}
			if !available {
				return ErrPriceChanged
			}
			return nil
		}
	}
	return ErrPriceChanged
}
func (s *Service) Confirm(ctx context.Context, actor int64, id string) (Operation, error) {
	// A repeated confirmation returns its original operation even after the quote expires.
	if op, e := s.Store.Get(ctx, id); e == nil {
		if op.Offer.Actor != actor {
			return Operation{}, ErrConflict
		}
		return op, nil
	}
	if s.TopologyReady != nil {
		if err := s.TopologyReady(ctx); err != nil {
			return Operation{}, err
		}
	}
	offer, e := s.Store.Offer(ctx, id)
	if e != nil {
		return Operation{}, e
	}
	if offer.Actor != actor {
		return Operation{}, ErrConflict
	}
	if e = s.checkOffer(ctx, offer); e != nil {
		return Operation{}, e
	}
	unlock, e := s.lockCapacity(ctx)
	if e != nil {
		return Operation{}, e
	}
	defer unlock()
	// A concurrent confirmation may have reserved this offer while we waited.
	// Return its identity before checking capacity, including the last free slot.
	if op, err := s.Store.Get(ctx, id); err == nil {
		if op.Offer.Actor != actor {
			return Operation{}, ErrConflict
		}
		return op, nil
	}
	if occupied, e := s.capacity(ctx); e != nil {
		return Operation{}, e
	} else if occupied >= MaxServers {
		return Operation{}, ErrLimit
	}
	return s.Store.Reserve(ctx, offer)
}
func (s *Service) Action(ctx context.Context, actor int64, id, action string) error {
	if actor <= 0 {
		return ErrConflict
	}
	unlock, e := s.Store.Lock(ctx)
	if e != nil {
		return e
	}
	defer unlock()
	if s.TopologyReady != nil {
		if err := s.TopologyReady(ctx); err != nil {
			return err
		}
	}
	op, e := s.Store.Get(ctx, id)
	if e != nil {
		return e
	}
	if isRetirementPhase(op.Phase) && action != "retry" {
		return ErrConflict
	}
	switch action {
	case "reinstall":
		// Recovery is limited to the staged, unpublished identity that failed
		// verification. Ready nodes use the coordinated fleet installer.
		if s.IsIngress(op) || op.State != "failed" || op.Phase != "verify" || op.InstanceID == "" || op.ExitID != op.ID ||
			op.InstallAttempt == ^uint64(0) {
			return ErrConflict
		}
		op.InstallAttempt++
		op.Reinstall = true
		op.Phase = "install"
		op.State = "pending"
		op.Error, op.ErrorMessage, op.HTTPStatus = "", "", 0
	case "retry":
		if op.State != "failed" {
			return ErrConflict
		}
		// An outstanding target reservation retains its attempt on retry, even
		// before job binding. Otherwise an explicit retry creates a generation.
		if op.Phase == "install" && op.ReinstallTarget == "" {
			if op.InstallAttempt == ^uint64(0) {
				return ErrConflict
			}
			op.InstallAttempt++
		}
		op.State = "pending"
		op.Error = ""
		op.ErrorMessage = ""
		op.HTTPStatus = 0
	case "cancel":
		if op.InstanceID != "" || op.Phase != "prepare" {
			return ErrConflict
		}
		op.State = "cancelled"
		if op.FirewallID != "" {
			op.State, op.Phase = "pending", "cancel_cleanup"
		}
		op.Charged = false
	case "delete":
		// Replayed requests must never resurrect a tombstone or rewind a saved
		// destructive phase after the provider resource has already disappeared.
		if op.State == "deleted" {
			return nil
		}
		if s.IsIngress(op) {
			return ErrIngressInUse
		}
		if op.InstanceID == "" {
			return ErrConflict
		}
		if op.ReinstallTarget != "" {
			releaser, ok := s.Provisioner.(interface {
				ReleaseReinstall(context.Context, *Operation) error
			})
			if !ok {
				return ErrConflict
			}
			if err := releaser.ReleaseReinstall(ctx, &op); err != nil {
				return err
			}
		}
		if op.Phase != "unpublish" && op.Phase != "delete" && op.Phase != "cleanup" {
			op.Phase = "unpublish"
		} else if op.State == "pending" {
			return nil
		}
		op.State = "pending"
		op.Error = ""
		op.ErrorMessage = ""
		op.HTTPStatus = 0
	default:
		return ErrConflict
	}
	if e = s.Store.Audit(ctx, actor, id, action); e != nil {
		return e
	}
	return s.Store.Save(ctx, op)
}
func (s *Service) Run(ctx context.Context) {
	s.run(ctx, 5*time.Second)
}

// Step advances one stage per operation so an ambiguous purchase cannot starve another node.
func (s *Service) lockTopology(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.LockTopology != nil {
		return s.LockTopology(ctx)
	}
	return func() {}, nil
}

func (s *Service) Step(ctx context.Context) error {
	release, err := s.lockTopology(ctx)
	if err != nil {
		return err
	}
	defer release()
	unlock, e := s.Store.Lock(ctx)
	if e != nil {
		return e
	}
	defer unlock()
	if s.TopologyReady != nil {
		if err := s.TopologyReady(ctx); err != nil {
			return err
		}
	}
	ops, e := s.Store.List(ctx)
	if e != nil {
		return e
	}
	var result error
	for _, op := range ops {
		if ctx.Err() != nil {
			return errors.Join(result, ctx.Err())
		}
		if op.State != "pending" && op.State != "unknown" {
			continue
		}
		result = errors.Join(result, s.advanceLogged(ctx, op))
	}
	return result
}
func (s *Service) fail(ctx context.Context, op Operation, code string, e error) error {
	op.State = "failed"
	op.Error = code
	if errors.Is(e, context.DeadlineExceeded) {
		switch op.Phase {
		case "publish":
			op.Error = "route_publication_timeout"
		case "apply":
			op.Error = "route_application_timeout"
		default:
			op.Error = "operation_timeout"
		}
	} else if provider := ErrorCode(e); provider != "operation_unavailable" && provider != "operation_timeout" {
		op.Error = provider
	}
	op.ErrorMessage = ErrorMessage(op.Error)
	var api APIError
	if errors.As(e, &api) {
		op.HTTPStatus = api.Status
	}
	if op.Error == "route_removal_failed" && errors.Is(e, ErrLastEnabledExit) {
		op.ErrorMessage = "Нельзя удалить последний включённый exit. Сначала добавьте и включите другой exit, затем повторите удаление. VPS не удалён и продолжает оплачиваться."
	}
	if errors.Is(e, ErrUnknownCreation) {
		op.State = "unknown"
	}
	checkpoint, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if save := s.Store.Save(checkpoint, op); save != nil {
		return save
	}
	return e
}
func (s *Service) advance(ctx context.Context, op Operation) error {
	if op.Phase == "cancel_cleanup" {
		if op.InstanceID != "" || op.Charged || s.Provisioner == nil {
			return s.fail(ctx, op, "resource_cleanup_failed", ErrConflict)
		}
		if err := s.Provisioner.Cleanup(ctx, &op); err != nil {
			return s.fail(ctx, op, "resource_cleanup_failed", err)
		}
		op.State = "cancelled"
		return s.Store.Save(ctx, op)
	}
	if isRetirementPhase(op.Phase) {
		return s.advanceRetirement(ctx, op)
	}
	if e := s.checkReplacement(ctx, op.Offer.ReplaceID); e != nil {
		return s.fail(ctx, op, ErrorCode(e), e)
	}
	if s.IsIngress(op) && (op.Phase == "unpublish" || op.Phase == "delete" || op.Phase == "cleanup") {
		return s.fail(ctx, op, "ingress_in_use", ErrIngressInUse)
	}

	if s.Provisioner == nil {
		return s.fail(ctx, op, "provisioner_unavailable", ErrUnavailable)
	}
	switch op.Phase {
	case "prepare":
		if occupied, e := s.capacity(ctx); e != nil {
			return s.fail(ctx, op, "capacity_check_failed", e)
		} else if occupied > MaxServers {
			return s.fail(ctx, op, "capacity_limit", ErrLimit)
		}
		if e := s.checkPurchaseOffer(ctx, op.Offer); e != nil {
			return s.fail(ctx, op, "offer_expired_or_changed", e)
		}
		req, e := s.Provisioner.Prepare(ctx, &op)
		if e != nil {
			return s.fail(ctx, op, "preparation_failed", e)
		}
		if e = s.checkPurchaseOffer(ctx, op.Offer); e != nil {
			return s.fail(ctx, op, "offer_expired_or_changed", e)
		}
		// Store provider IDs before creating the paid resource; a timeout after this point is never blindly retried.
		op.Phase = "creating"
		op.Charged = true
		if e = s.Store.Save(ctx, op); e != nil {
			return e
		}
		req.Region = op.Offer.Region.ID
		req.Plan = op.Offer.Plan.ID
		req.Tags = []string{"ultra", "ultra-operation-" + op.ID}
		req.Label = "ultra-" + op.Offer.Region.ID
		req.Backups = "disabled"
		instance, e := s.API.Create(ctx, req)
		if e != nil {
			var api APIError
			if errors.As(e, &api) && api.Status >= 400 && api.Status < 500 && api.Status != 408 {
				op.Phase = "prepare"
				op.Charged = false
				return s.fail(ctx, op, "creation_rejected", e)
			}
			return s.fail(ctx, op, "creation_requires_reconciliation", errors.Join(ErrUnknownCreation, e))
		}
		op.InstanceID = instance.ID
		op.Phase = "install"
	case "creating":
		instances, e := s.API.Instances(ctx)
		if e != nil {
			return s.fail(ctx, op, "reconciliation_unavailable", ErrUnknownCreation)
		}
		matches := []Instance{}
		for _, i := range instances {
			for _, tag := range i.Tags {
				if tag == "ultra-operation-"+op.ID {
					matches = append(matches, i)
					break
				}
			}
		}
		if len(matches) != 1 {
			return s.fail(ctx, op, "creation_ambiguous", ErrUnknownCreation)
		}
		if matches[0].Region != op.Offer.Region.ID || matches[0].Plan != op.Offer.Plan.ID {
			return s.fail(ctx, op, "resource_mismatch", ErrConflict)
		}
		op.InstanceID = matches[0].ID
		op.Phase = "install"
		op.State = "pending"
		op.Error = ""
		op.ErrorMessage = ""
		op.HTTPStatus = 0
	case "install", "verify":
		instance, e := s.API.Get(ctx, op.InstanceID)
		if e != nil {
			return s.fail(ctx, op, "instance_unavailable", e)
		}
		if instance.Status != "active" || instance.IP == "" {
			return nil
		}
		if op.Phase == "install" {
			if e = s.Provisioner.Install(ctx, &op, instance); e != nil {
				return s.fail(ctx, op, "installation_failed", e)
			}
			op.Phase = "verify"
		} else {
			if e = s.Provisioner.Verify(ctx, &op, instance); e != nil {
				return s.fail(ctx, op, "tunnel_verification_failed", e)
			}
			op.Phase = "publish"
		}
	case "publish":
		if e := s.Provisioner.Publish(ctx, &op); e != nil {
			return s.fail(ctx, op, "route_publication_failed", e)
		}
		op.Phase = "apply"
	case "apply":
		if e := s.Provisioner.ApplyRoute(ctx, &op); e != nil {
			return s.fail(ctx, op, "route_application_failed", e)
		}
		if op.Offer.ReplaceID != "" {
			op.Phase = "replace_old"
		} else {
			op.State = "ready"
			op.Phase = "ready"
		}
	case "replace_old":
		old, e := s.Store.Get(ctx, op.Offer.ReplaceID)
		if e != nil {
			return s.fail(ctx, op, "old_resource_unavailable", e)
		}
		if old.State != "deleted" {
			if e = s.Provisioner.Unpublish(ctx, &old); e != nil {
				return s.fail(ctx, op, "old_route_removal_failed", e)
			}
			if e = s.API.Delete(ctx, old.InstanceID); e != nil {
				return s.fail(ctx, op, "old_server_deletion_failed", e)
			}
			if e = s.Provisioner.Cleanup(ctx, &old); e != nil {
				return s.fail(ctx, op, "old_resource_cleanup_failed", e)
			}
			old.State = "deleted"
			old.Charged = false
			if e = s.Store.Save(ctx, old); e != nil {
				return e
			}
		}
		op.State = "ready"
		op.Phase = "ready"
	case "unpublish":
		if err := s.Provisioner.ValidateDelete(ctx, &op); err != nil {
			return s.fail(ctx, op, "deletion_protected", err)
		}
		if e := s.Provisioner.Unpublish(ctx, &op); e != nil {
			return s.fail(ctx, op, "route_removal_failed", e)
		}
		op.Phase = "delete"
	case "delete":
		if err := s.Provisioner.ValidateDelete(ctx, &op); err != nil {
			return s.fail(ctx, op, "deletion_protected", err)
		}
		if e := s.API.Delete(ctx, op.InstanceID); e != nil {
			return s.fail(ctx, op, "server_deletion_failed", e)
		}
		op.Phase = "cleanup"
	case "cleanup":
		if err := s.Provisioner.ValidateDelete(ctx, &op); err != nil {
			return s.fail(ctx, op, "deletion_protected", err)
		}
		if e := s.Provisioner.Cleanup(ctx, &op); e != nil {
			return s.fail(ctx, op, "resource_cleanup_failed", e)
		}
		op.State = "deleted"
		op.Charged = false
	default:
		return fmt.Errorf("unknown operation phase")
	}
	return s.Store.Save(ctx, op)
}

// RetirementTarget binds an operator-approved plan to persisted provider identities.
type RetirementTarget struct {
	OperationID string `json:"operation_id"`
	InstanceID  string `json:"instance_id"`
}

// RetireExits checkpoints every selected operation before any destructive effect.
// Replaying the same plan resumes saved phases; deleted operations remain tombstones.
func (s *Service) RetireExits(ctx context.Context, actor int64, targets []RetirementTarget) error {
	if actor <= 0 || len(targets) == 0 || s.Provisioner == nil {
		return ErrConflict
	}
	release, err := s.lockTopology(ctx)
	if err != nil {
		return err
	}
	defer release()
	unlock, err := s.Store.Lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if s.TopologyReady != nil {
		if err = s.TopologyReady(ctx); err != nil {
			return err
		}
	}
	// Instances consumes the provider's complete cursor-paginated inventory.
	instances, err := s.API.Instances(ctx)
	if err != nil {
		return err
	}
	selected := make([]Operation, 0, len(targets))
	seen := map[string]bool{}
	for _, target := range targets {
		if target.OperationID == "" || target.InstanceID == "" || seen[target.OperationID] {
			return ErrConflict
		}
		seen[target.OperationID] = true
		op, err := s.Store.Get(ctx, target.OperationID)
		if err != nil {
			return err
		}
		if op.ID != target.OperationID || op.InstanceID != target.InstanceID ||
			(op.ExitID != "" && op.ExitID != op.ID) || op.ReinstallTarget != "" || s.IsIngress(op) || op.ServesSubscriptionIngress {
			return ErrConflict
		}
		if isRetirementPhase(op.Phase) && !validRetirementTarget(op.RetirementTarget) {
			return ErrConflict
		}
		if !isRetirementPhase(op.Phase) && op.State != "ready" && op.State != "failed" && op.State != "pending" {
			return ErrConflict
		}
		found := false
		for _, instance := range instances {
			if instance.ID == target.InstanceID {
				if found || !retirementOwned(op, instance) {
					return ErrConflict
				}
				found = true
				if !isRetirementPhase(op.Phase) {
					if !validRetirementTarget(instance.IP) || op.RetirementTarget != "" {
						return ErrConflict
					}
					op.RetirementTarget = net.ParseIP(instance.IP).String()
				} else if !sameRetirementTarget(op.RetirementTarget, instance.IP) {
					return ErrConflict
				}
				if err := s.validateRetirement(ctx, op, instance); err != nil {
					return err
				}
			}
		}
		if !found && !isRetirementPhase(op.Phase) {
			return ErrConflict
		}
		if !found {
			if err := s.validateRetirement(ctx, op, Instance{ID: op.InstanceID, IP: op.RetirementTarget}); err != nil {
				return err
			}
		}
		if op.State == "deleted" {
			continue
		}
		selected = append(selected, op)
	}
	for i := range selected {
		op := &selected[i]
		if !isRetirementPhase(op.Phase) {
			op.Phase = "retire_unpublish"
		}
		op.State, op.Error, op.ErrorMessage, op.HTTPStatus = "pending", "", "", 0
		if err := s.Store.Audit(ctx, actor, op.ID, "retire"); err != nil {
			return err
		}
		if err := s.Store.Save(ctx, *op); err != nil {
			return err
		}
	}
	var result error
	for _, op := range selected {
		for range 3 {
			current, err := s.Store.Get(ctx, op.ID)
			if err != nil {
				result = errors.Join(result, err)
				break
			}
			if current.State == "deleted" {
				break
			}
			if err := s.advanceLogged(ctx, current); err != nil {
				result = errors.Join(result, err)
				break
			}
		}
	}
	return result
}

func isRetirementPhase(phase string) bool {
	return phase == "retire_unpublish" || phase == "retire_delete" || phase == "retire_cleanup"
}

func validRetirementTarget(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && ip.To4() != nil
}

func sameRetirementTarget(a, b string) bool {
	left, right := net.ParseIP(a), net.ParseIP(b)
	return left != nil && right != nil && left.Equal(right)
}

func retirementOwned(op Operation, instance Instance) bool {
	if instance.ID != op.InstanceID || len(instance.Tags) != 2 {
		return false
	}
	return (instance.Tags[0] == "ultra" && instance.Tags[1] == "ultra-operation-"+op.ID) ||
		(instance.Tags[1] == "ultra" && instance.Tags[0] == "ultra-operation-"+op.ID)
}

func (s *Service) validateRetirement(ctx context.Context, op Operation, instance Instance) error {
	validator, ok := s.Provisioner.(interface {
		ValidateRetirement(context.Context, *Operation, Instance) error
	})
	if !ok {
		return ErrUnavailable
	}
	return validator.ValidateRetirement(ctx, &op, instance)
}

func (s *Service) advanceRetirement(ctx context.Context, op Operation) error {
	if s.Provisioner == nil || op.ID == "" || op.InstanceID == "" || (op.ExitID != "" && op.ExitID != op.ID) ||
		s.IsIngress(op) || op.ServesSubscriptionIngress || op.ReinstallTarget != "" || !validRetirementTarget(op.RetirementTarget) {
		return s.fail(ctx, op, "retirement_protected", ErrConflict)
	}
	// Check ownership immediately before every destructive stage, including resume.
	instance, err := s.API.Get(ctx, op.InstanceID)
	var api APIError
	missing := errors.As(err, &api) && api.Status == 404
	if err != nil && !missing {
		return s.fail(ctx, op, "retirement_inventory_failed", err)
	}
	if !missing && (!retirementOwned(op, instance) || !sameRetirementTarget(op.RetirementTarget, instance.IP)) {
		return s.fail(ctx, op, "retirement_ownership_mismatch", ErrConflict)
	}
	if missing {
		instance = Instance{ID: op.InstanceID, IP: op.RetirementTarget}
	}
	if err = s.validateRetirement(ctx, op, instance); err != nil {
		return s.fail(ctx, op, "retirement_protected", err)
	}
	switch op.Phase {
	case "retire_unpublish":
		if err = s.Provisioner.Unpublish(ctx, &op); err != nil {
			return s.fail(ctx, op, "route_removal_failed", err)
		}
		op.Phase = "retire_delete"
	case "retire_delete":
		if !missing {
			if err = s.API.Delete(ctx, op.InstanceID); err != nil {
				return s.fail(ctx, op, "server_deletion_failed", err)
			}
		}
		op.Phase = "retire_cleanup"
	case "retire_cleanup":
		if err = s.Provisioner.Cleanup(ctx, &op); err != nil {
			return s.fail(ctx, op, "resource_cleanup_failed", err)
		}
		op.State, op.Charged = "deleted", false
	}
	return s.Store.Save(ctx, op)
}

// capacity includes unmanaged instances without granting Ultra ownership of them.
func (s *Service) capacity(ctx context.Context) (int, error) {
	instances, e := s.API.Instances(ctx)
	if e != nil {
		return 0, e
	}
	ops, e := s.Store.List(ctx)
	if e != nil {
		return 0, e
	}
	physical := map[string]Instance{}
	for _, instance := range instances {
		if instance.ID == "" {
			return 0, ErrConflict
		}
		physical[instance.ID] = instance
	}
	occupied := len(physical)
	claimed := map[string]bool{}
	for _, op := range ops {
		if op.State == "deleted" || op.State == "cancelled" {
			continue
		}
		matched := ""
		if _, exists := physical[op.InstanceID]; exists && !claimed[op.InstanceID] {
			matched = op.InstanceID
		} else if op.InstanceID == "" {
			for id, instance := range physical {
				if claimed[id] {
					continue
				}
				for _, tag := range instance.Tags {
					if tag == "ultra-operation-"+op.ID {
						matched = id
						break
					}
				}
				if matched != "" {
					break
				}
			}
		}
		if matched == "" {
			occupied++
		} else {
			// A reservation accounts for at most one physical machine, even
			// when an ambiguous creation produced several with the same tag.
			claimed[matched] = true
		}
	}
	return occupied, nil
}

// IsIngress protects the infrastructure identity, independently of VPN health.
func (s *Service) IsIngress(op Operation) bool {
	return s.IngressInstanceID != "" && op.InstanceID == s.IngressInstanceID
}
func (s *Service) checkReplacement(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	old, err := s.Store.Get(ctx, id)
	if err != nil {
		return err
	}
	if s.IsIngress(old) {
		return ErrIngressInUse
	}
	return nil
}
