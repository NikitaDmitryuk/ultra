package db

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/db/sqlc"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	xrayuuid "github.com/xtls/xray-core/common/uuid"
)

var (
	ErrExitNotFound      = errors.New("exit node not found")
	ErrExitLastEnabled   = errors.New("cannot remove or disable the last enabled exit node")
	ErrExitDuplicateAddr = errors.New("enabled exit with this address and port already exists")
	ErrExitDuplicateUUID = errors.New("exit with this tunnel_uuid already exists")
)

// ExitNodeRepo manages exit_nodes rows on the bridge PostgreSQL.
type ExitNodeRepo struct {
	db *DB
}

func NewExitNodeRepo(db *DB) *ExitNodeRepo {
	return &ExitNodeRepo{db: db}
}

func exitNodeFromFields(id pgtype.UUID, name, address string, port int32, tunnelUUID, pin string, priority int32, enabled bool, createdAt, updatedAt pgtype.Timestamptz) exits.Node {
	return exits.Node{
		ID:                   fromPGUUID(id),
		Name:                 name,
		Address:              address,
		Port:                 int(port),
		TunnelUUID:           tunnelUUID,
		PinnedPeerCertSHA256: pin,
		Priority:             int(priority),
		Enabled:              enabled,
		CreatedAt:            timeFromPG(createdAt),
		UpdatedAt:            timeFromPG(updatedAt),
	}
}

func exitNodeFromList(row sqlc.ListExitNodesRow) exits.Node {
	return exitNodeFromFields(row.ID, row.Name, row.Address, row.Port, row.TunnelUuid, row.PinnedPeerCertSha256, row.Priority, row.Enabled, row.CreatedAt, row.UpdatedAt)
}

func exitNodeFromGet(row sqlc.GetExitNodeRow) exits.Node {
	return exitNodeFromFields(row.ID, row.Name, row.Address, row.Port, row.TunnelUuid, row.PinnedPeerCertSha256, row.Priority, row.Enabled, row.CreatedAt, row.UpdatedAt)
}

func exitNodeFromInsert(row sqlc.InsertExitNodeRow) exits.Node {
	return exitNodeFromFields(row.ID, row.Name, row.Address, row.Port, row.TunnelUuid, row.PinnedPeerCertSha256, row.Priority, row.Enabled, row.CreatedAt, row.UpdatedAt)
}

func exitNodeFromUpdate(row sqlc.UpdateExitNodeRow) exits.Node {
	return exitNodeFromFields(row.ID, row.Name, row.Address, row.Port, row.TunnelUuid, row.PinnedPeerCertSha256, row.Priority, row.Enabled, row.CreatedAt, row.UpdatedAt)
}

func (r *ExitNodeRepo) List(ctx context.Context) ([]exits.Node, error) {
	rows, err := r.db.Queries.ListExitNodes(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]exits.Node, 0, len(rows))
	for _, row := range rows {
		out = append(out, exitNodeFromList(row))
	}
	return out, nil
}

func (r *ExitNodeRepo) ListEnabled(ctx context.Context) ([]exits.Node, error) {
	all, err := r.List(ctx)
	if err != nil {
		return nil, err
	}
	return exits.FilterEnabled(all), nil
}

func (r *ExitNodeRepo) Get(ctx context.Context, id string) (exits.Node, error) {
	pgID, err := toPGUUID(id)
	if err != nil {
		return exits.Node{}, err
	}
	row, err := r.db.Queries.GetExitNode(ctx, pgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return exits.Node{}, ErrExitNotFound
	}
	return exitNodeFromGet(row), err
}

func (r *ExitNodeRepo) CountEnabled(ctx context.Context) (int, error) {
	n, err := r.db.Queries.CountEnabledExitNodes(ctx)
	return int(n), err
}

// Bootstrap imports exit nodes from bootstrap file (preferred) or spec.exit, merging new rows.
func (r *ExitNodeRepo) Bootstrap(ctx context.Context, spec *config.Spec, bootstrapPath string) error {
	entries, err := exits.LoadBootstrapFile(bootstrapPath)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		if spec == nil || spec.Exit.Address == "" || spec.Exit.Port <= 0 || spec.Exit.TunnelUUID == "" {
			return errors.New("no exit nodes configured (missing bootstrap file and spec.exit)")
		}
		entries = []exits.BootstrapEntry{{
			Name:       "primary",
			Address:    spec.Exit.Address,
			Port:       spec.Exit.Port,
			TunnelUUID: spec.Exit.TunnelUUID,
			Priority:   100,
		}}
	}
	for _, e := range entries {
		if err := r.mergeBootstrapEntry(ctx, e); err != nil {
			return err
		}
	}
	return nil
}

func (r *ExitNodeRepo) mergeBootstrapEntry(ctx context.Context, e exits.BootstrapEntry) error {
	name := strings.TrimSpace(e.Name)
	if name == "" {
		name = "exit"
	}
	priority := e.Priority
	if priority <= 0 {
		priority = 100
	}
	tunnelUUID := strings.TrimSpace(e.TunnelUUID)
	enabled := e.EnabledOrDefault()
	address := strings.TrimSpace(e.Address)
	pin := strings.TrimSpace(e.PinnedPeerCertSHA256)
	now := time.Now().UTC()

	if address != "" && e.Port > 0 {
		id, err := r.db.Queries.FindExitNodeByAddressPort(ctx, sqlc.FindExitNodeByAddressPortParams{Address: address, Port: int32(e.Port)})
		if err == nil {
			return r.db.Queries.MergeExitByAddressPort(ctx, sqlc.MergeExitByAddressPortParams{
				ID:        id,
				Name:      name,
				Column3:   tunnelUUID,
				Column4:   pin,
				Column5:   priority,
				Enabled:   enabled,
				UpdatedAt: toPGTime(now),
			})
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}

	if tunnelUUID != "" {
		id, err := r.db.Queries.FindExitNodeByTunnelUUID(ctx, tunnelUUID)
		if err == nil {
			return r.db.Queries.MergeExitByTunnelUUID(ctx, sqlc.MergeExitByTunnelUUIDParams{
				ID:        id,
				Name:      name,
				Column3:   pin,
				Column4:   priority,
				Enabled:   enabled,
				UpdatedAt: toPGTime(now),
			})
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}

	enabledPtr := enabled
	_, err := r.Add(ctx, exits.AddParams{
		Name:                 name,
		Address:              e.Address,
		Port:                 e.Port,
		TunnelUUID:           e.TunnelUUID,
		PinnedPeerCertSHA256: e.PinnedPeerCertSHA256,
		Priority:             priority,
		Enabled:              &enabledPtr,
	})
	return err
}

// BootstrapFromSpec is deprecated; calls Bootstrap with an empty bootstrap path.
func (r *ExitNodeRepo) BootstrapFromSpec(ctx context.Context, spec *config.Spec) error {
	return r.Bootstrap(ctx, spec, "")
}

// Add inserts a new exit node (generates id and tunnel_uuid when empty).
func (r *ExitNodeRepo) Add(ctx context.Context, p exits.AddParams) (exits.Node, error) {
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return exits.Node{}, errors.New("exit name required")
	}
	address := strings.TrimSpace(p.Address)
	if address == "" || p.Port <= 0 || p.Port > 65535 {
		return exits.Node{}, errors.New("exit address and port required")
	}
	tunnelUUID := strings.TrimSpace(p.TunnelUUID)
	if tunnelUUID == "" {
		newID := xrayuuid.New()
		tunnelUUID = (&newID).String()
	}
	priority := p.Priority
	if priority <= 0 {
		priority = 100
	}
	id := strings.TrimSpace(p.ID)
	if id == "" {
		id = uuid.NewString()
	}
	pgID, err := toPGUUID(id)
	if err != nil {
		return exits.Node{}, err
	}

	exists, err := r.db.Queries.CountExitNodesByTunnelUUID(ctx, tunnelUUID)
	if err != nil {
		return exits.Node{}, err
	}
	if exists > 0 {
		return exits.Node{}, ErrExitDuplicateUUID
	}
	exists, err = r.db.Queries.CountEnabledExitNodesByAddressPort(ctx, sqlc.CountEnabledExitNodesByAddressPortParams{Address: address, Port: int32(p.Port)})
	if err != nil {
		return exits.Node{}, err
	}
	if exists > 0 {
		return exits.Node{}, ErrExitDuplicateAddr
	}

	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}

	row, err := r.db.Queries.InsertExitNode(ctx, sqlc.InsertExitNodeParams{
		ID:                   pgID,
		Name:                 name,
		Address:              address,
		Port:                 int32(p.Port),
		TunnelUuid:           tunnelUUID,
		PinnedPeerCertSha256: strings.TrimSpace(p.PinnedPeerCertSHA256),
		Priority:             int32(priority),
		Enabled:              enabled,
	})
	if err != nil {
		return exits.Node{}, err
	}
	return exitNodeFromInsert(row), nil
}

func (r *ExitNodeRepo) Update(ctx context.Context, id string, patch exits.UpdatePatch) (exits.Node, error) {
	cur, err := r.Get(ctx, id)
	if err != nil {
		return exits.Node{}, err
	}
	name := cur.Name
	if patch.Name != nil {
		name = strings.TrimSpace(*patch.Name)
		if name == "" {
			return exits.Node{}, errors.New("exit name required")
		}
	}
	address := cur.Address
	if patch.Address != nil {
		address = strings.TrimSpace(*patch.Address)
		if address == "" {
			return exits.Node{}, errors.New("exit address required")
		}
	}
	port := cur.Port
	if patch.Port != nil {
		port = *patch.Port
		if port <= 0 || port > 65535 {
			return exits.Node{}, errors.New("invalid port")
		}
	}
	priority := cur.Priority
	if patch.Priority != nil {
		priority = *patch.Priority
		if priority <= 0 {
			return exits.Node{}, errors.New("priority must be positive")
		}
	}
	enabled := cur.Enabled
	if patch.Enabled != nil {
		enabled = *patch.Enabled
	}
	if !enabled {
		count, err := r.CountEnabled(ctx)
		if err != nil {
			return exits.Node{}, err
		}
		if count <= 1 && cur.Enabled {
			return exits.Node{}, ErrExitLastEnabled
		}
	}
	if enabled {
		pgID, err := toPGUUID(id)
		if err != nil {
			return exits.Node{}, err
		}
		dup, err := r.db.Queries.CountEnabledExitNodeDuplicate(ctx, sqlc.CountEnabledExitNodeDuplicateParams{
			Address: address,
			Port:    int32(port),
			ID:      pgID,
		})
		if err != nil {
			return exits.Node{}, err
		}
		if dup > 0 {
			return exits.Node{}, ErrExitDuplicateAddr
		}
	}

	pgID, err := toPGUUID(id)
	if err != nil {
		return exits.Node{}, err
	}
	row, err := r.db.Queries.UpdateExitNode(ctx, sqlc.UpdateExitNodeParams{
		ID:        pgID,
		Name:      name,
		Address:   address,
		Port:      int32(port),
		Priority:  int32(priority),
		Enabled:   enabled,
		UpdatedAt: toPGTime(time.Now().UTC()),
	})
	if err != nil {
		return exits.Node{}, err
	}
	return exitNodeFromUpdate(row), nil
}

func (r *ExitNodeRepo) Delete(ctx context.Context, id string) error {
	cur, err := r.Get(ctx, id)
	if err != nil {
		return err
	}
	if cur.Enabled {
		count, err := r.CountEnabled(ctx)
		if err != nil {
			return err
		}
		if count <= 1 {
			return ErrExitLastEnabled
		}
	}
	pgID, err := toPGUUID(id)
	if err != nil {
		return err
	}
	affected, err := r.db.Queries.DeleteExitNode(ctx, pgID)
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrExitNotFound
	}
	return nil
}
