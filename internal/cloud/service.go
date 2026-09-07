package cloud

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
)

var ErrLimit = errors.New("two cloud slots already reserved")
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
	ErrorMessage     string    `json:"error_message,omitempty"`
	HTTPStatus       int       `json:"http_status,omitempty"`
	ReplicationState string    `json:"replication_state,omitempty"`
	ID               string    `json:"id"`
	Offer            Offer     `json:"offer"`
	State            string    `json:"state"`
	Phase            string    `json:"phase"`
	InstanceID       string    `json:"instance_id,omitempty"`
	ExitID           string    `json:"exit_id,omitempty"`
	FirewallID       string    `json:"firewall_id,omitempty"`
	Error            string    `json:"error,omitempty"`
	Charged          bool      `json:"charged"`
	CreatedAt        time.Time `json:"created_at"`
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
	Unpublish(context.Context, *Operation) error
	Cleanup(context.Context, *Operation) error
}
type Service struct {
	Log         *slog.Logger
	API         Provider
	Store       Store
	Provisioner Provisioner
	Now         func() time.Time
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
		return Offer{}, errors.New("plan unavailable in region")
	}
	offer := Offer{ID: uuid.NewString(), Actor: actor, Region: selected, Plan: tariff, Price: price, ExpiresAt: s.now().Add(5 * time.Minute), ReplaceID: replace}
	return offer, s.Store.SaveOffer(ctx, offer)
}
func (s *Service) checkOffer(ctx context.Context, o Offer) error {
	if !s.now().Before(o.ExpiresAt) {
		return ErrPriceChanged
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
	if occupied, e := s.capacity(ctx); e != nil {
		return Operation{}, e
	} else if occupied >= 2 {
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
	op, e := s.Store.Get(ctx, id)
	if e != nil {
		return e
	}
	switch action {
	case "retry":
		if op.State != "failed" && op.State != "unknown" {
			return ErrConflict
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
		op.Charged = false
	case "delete":
		if op.InstanceID == "" {
			return ErrConflict
		}
		op.State = "pending"
		op.Phase = "unpublish"
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
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = s.Step(ctx)
		}
	}
}

// Step advances one stage per operation so an ambiguous purchase cannot starve another node.
func (s *Service) Step(ctx context.Context) error {
	unlock, e := s.Store.Lock(ctx)
	if e != nil {
		return e
	}
	defer unlock()
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
	if provider := ErrorCode(e); provider != "operation_unavailable" {
		op.Error = provider
	}
	op.ErrorMessage = ErrorMessage(op.Error)
	var api APIError
	if errors.As(e, &api) {
		op.HTTPStatus = api.Status
	}
	if errors.Is(e, ErrUnknownCreation) {
		op.State = "unknown"
	}
	if save := s.Store.Save(ctx, op); save != nil {
		return save
	}
	return e
}
func (s *Service) advance(ctx context.Context, op Operation) error {
	if s.Provisioner == nil {
		return s.fail(ctx, op, "provisioner_unavailable", ErrUnavailable)
	}
	switch op.Phase {
	case "prepare":
		if occupied, e := s.capacity(ctx); e != nil {
			return s.fail(ctx, op, "capacity_check_failed", e)
		} else if occupied > 2 {
			return s.fail(ctx, op, "capacity_limit", ErrLimit)
		}
		if e := s.checkOffer(ctx, op.Offer); e != nil {
			return s.fail(ctx, op, "offer_expired_or_changed", e)
		}
		req, e := s.Provisioner.Prepare(ctx, &op)
		if e != nil {
			return s.fail(ctx, op, "preparation_failed", e)
		}
		if e = s.checkOffer(ctx, op.Offer); e != nil {
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
			return s.fail(ctx, op, "configuration_not_applied", e)
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
		if e := s.Provisioner.Unpublish(ctx, &op); e != nil {
			return s.fail(ctx, op, "route_removal_failed", e)
		}
		op.Phase = "delete"
	case "delete":
		if e := s.API.Delete(ctx, op.InstanceID); e != nil {
			return s.fail(ctx, op, "server_deletion_failed", e)
		}
		op.Phase = "cleanup"
	case "cleanup":
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
	occupied := 0
	known := map[string]bool{}
	tags := map[string]bool{}
	for _, op := range ops {
		if op.State != "deleted" && op.State != "cancelled" {
			occupied++
			known[op.InstanceID] = true
			tags["ultra-operation-"+op.ID] = true
		}
	}
	for _, instance := range instances {
		accounted := known[instance.ID]
		for _, tag := range instance.Tags {
			accounted = accounted || tags[tag]
		}
		if !accounted {
			occupied++
		}
	}
	return occupied, nil
}
