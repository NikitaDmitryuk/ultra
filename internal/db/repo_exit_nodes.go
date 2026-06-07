package db

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/NikitaDmitryuk/ultra/internal/config"
	"github.com/NikitaDmitryuk/ultra/internal/exits"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	xrayuuid "github.com/xtls/xray-core/common/uuid"
)

var (
	ErrExitNotFound        = errors.New("exit node not found")
	ErrExitLastEnabled     = errors.New("cannot remove or disable the last enabled exit node")
	ErrExitDuplicateAddr   = errors.New("enabled exit with this address and port already exists")
	ErrExitDuplicateUUID   = errors.New("exit with this tunnel_uuid already exists")
)

// ExitNodeRepo manages exit_nodes rows on the bridge PostgreSQL.
type ExitNodeRepo struct {
	db *DB
}

func NewExitNodeRepo(db *DB) *ExitNodeRepo {
	return &ExitNodeRepo{db: db}
}

const exitNodeCols = `id, name, address, port, tunnel_uuid, pinned_peer_cert_sha256, priority, enabled, created_at, updated_at`

func scanExitNode(row pgx.Row) (exits.Node, error) {
	var n exits.Node
	err := row.Scan(&n.ID, &n.Name, &n.Address, &n.Port, &n.TunnelUUID, &n.PinnedPeerCertSHA256, &n.Priority, &n.Enabled, &n.CreatedAt, &n.UpdatedAt)
	return n, err
}

func (r *ExitNodeRepo) List(ctx context.Context) ([]exits.Node, error) {
	rows, err := r.db.Pool.Query(ctx, `
		SELECT `+exitNodeCols+` FROM exit_nodes ORDER BY priority ASC, created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []exits.Node
	for rows.Next() {
		n, err := scanExitNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (r *ExitNodeRepo) ListEnabled(ctx context.Context) ([]exits.Node, error) {
	all, err := r.List(ctx)
	if err != nil {
		return nil, err
	}
	return exits.FilterEnabled(all), nil
}

func (r *ExitNodeRepo) Get(ctx context.Context, id string) (exits.Node, error) {
	row := r.db.Pool.QueryRow(ctx, `SELECT `+exitNodeCols+` FROM exit_nodes WHERE id=$1`, id)
	n, err := scanExitNode(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return exits.Node{}, ErrExitNotFound
	}
	return n, err
}

func (r *ExitNodeRepo) CountEnabled(ctx context.Context) (int, error) {
	var n int
	err := r.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM exit_nodes WHERE enabled=TRUE`).Scan(&n)
	return n, err
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
		var id string
		err := r.db.Pool.QueryRow(ctx,
			`SELECT id FROM exit_nodes WHERE address=$1 AND port=$2`, address, e.Port,
		).Scan(&id)
		if err == nil {
			_, err := r.db.Pool.Exec(ctx, `
				UPDATE exit_nodes SET
					name=$2,
					tunnel_uuid=CASE WHEN $3<>'' THEN $3 ELSE tunnel_uuid END,
					pinned_peer_cert_sha256=CASE WHEN $4<>'' THEN $4 ELSE pinned_peer_cert_sha256 END,
					priority=CASE WHEN $5>0 THEN $5 ELSE priority END,
					enabled=$6,
					updated_at=$7
				WHERE id=$1`,
				id, name, tunnelUUID, pin, priority, enabled, now,
			)
			return err
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
	}

	if tunnelUUID != "" {
		var id string
		err := r.db.Pool.QueryRow(ctx,
			`SELECT id FROM exit_nodes WHERE tunnel_uuid=$1`, tunnelUUID,
		).Scan(&id)
		if err == nil {
			_, err := r.db.Pool.Exec(ctx, `
				UPDATE exit_nodes SET
					name=$2,
					pinned_peer_cert_sha256=CASE WHEN $3<>'' THEN $3 ELSE pinned_peer_cert_sha256 END,
					priority=CASE WHEN $4>0 THEN $4 ELSE priority END,
					enabled=$5,
					updated_at=$6
				WHERE id=$1`,
				id, name, pin, priority, enabled, now,
			)
			return err
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

	var exists int
	if err := r.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM exit_nodes WHERE tunnel_uuid=$1`, tunnelUUID,
	).Scan(&exists); err != nil {
		return exits.Node{}, err
	}
	if exists > 0 {
		return exits.Node{}, ErrExitDuplicateUUID
	}
	if err := r.db.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM exit_nodes WHERE enabled=TRUE AND address=$1 AND port=$2`,
		address, p.Port,
	).Scan(&exists); err != nil {
		return exits.Node{}, err
	}
	if exists > 0 {
		return exits.Node{}, ErrExitDuplicateAddr
	}

	enabled := true
	if p.Enabled != nil {
		enabled = *p.Enabled
	}

	row := r.db.Pool.QueryRow(ctx, `
		INSERT INTO exit_nodes(id, name, address, port, tunnel_uuid, pinned_peer_cert_sha256, priority, enabled)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING `+exitNodeCols,
		id, name, address, p.Port, tunnelUUID, strings.TrimSpace(p.PinnedPeerCertSHA256), priority, enabled,
	)
	return scanExitNode(row)
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
		var dup int
		if err := r.db.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM exit_nodes WHERE enabled=TRUE AND address=$1 AND port=$2 AND id<>$3`,
			address, port, id,
		).Scan(&dup); err != nil {
			return exits.Node{}, err
		}
		if dup > 0 {
			return exits.Node{}, ErrExitDuplicateAddr
		}
	}

	row := r.db.Pool.QueryRow(ctx, `
		UPDATE exit_nodes SET name=$2, address=$3, port=$4, priority=$5, enabled=$6, updated_at=$7
		WHERE id=$1
		RETURNING `+exitNodeCols,
		id, name, address, port, priority, enabled, time.Now().UTC(),
	)
	return scanExitNode(row)
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
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM exit_nodes WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrExitNotFound
	}
	return nil
}
