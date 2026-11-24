package database

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s/internal/purl"
)

// Suppression is a team's current assessment that a vulnerability does not
// matter for a package in an image name, in one workload. It applies until deleted.
type Suppression struct {
	SuppressionKey
	Team      string    `json:"team"`
	State     string    `json:"state"` // not_affected, false_positive or accepted_risk
	Detail    string    `json:"detail"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// SuppressionKey identifies a team's suppression. Stored keys hold a package key
// and a vulnerability ID; requests may give a purl and an alias.
type SuppressionKey struct {
	Environment     string `json:"environment"`
	Workload        string `json:"workload"`
	ImageName       string `json:"image_name"`
	Package         string `json:"package_key"`      // package key, or a purl whose version, qualifiers and subpath are dropped
	VulnerabilityID string `json:"vulnerability_id"` // ID, or an alias naming exactly one vulnerability
}

// suppressionColumns are the columns of suppressions s that collectSuppression reads.
const suppressionColumns = `s.team, s.environment, s.workload, s.image_name, s.package_key, s.vulnerability_id, s.state, s.detail,
	s.updated_by, s.updated_at`

func collectSuppression(row pgx.CollectableRow) (Suppression, error) {
	var s Suppression
	err := row.Scan(&s.Team, &s.Environment, &s.Workload, &s.ImageName, &s.Package, &s.VulnerabilityID, &s.State, &s.Detail, &s.UpdatedBy, &s.UpdatedAt)
	return s, err
}

// NewSuppression is a suppression to set.
type NewSuppression struct {
	SuppressionKey
	State  string // not_affected, false_positive or accepted_risk
	Detail string
}

func (n NewSuppression) validate() error {
	switch {
	case n.State != "not_affected" && n.State != "false_positive" && n.State != "accepted_risk":
		return fmt.Errorf("invalid state %q: %w", n.State, ErrInvalid)
	case n.Detail == "":
		return fmt.Errorf("detail is required: %w", ErrInvalid)
	}
	return nil
}

// canonical returns k with its package as a package key and its vulnerability as an ID.
func (k SuppressionKey) canonical(ctx context.Context, q pgxQuerier) (SuppressionKey, error) {
	if k.Environment == "" || k.Workload == "" {
		return SuppressionKey{}, fmt.Errorf("environment and workload are required: %w", ErrInvalid)
	}
	if k.ImageName == "" {
		return SuppressionKey{}, fmt.Errorf("image name is required: %w", ErrInvalid)
	}
	if k.VulnerabilityID == "" {
		return SuppressionKey{}, fmt.Errorf("vulnerability ID is required: %w", ErrInvalid)
	}
	pkg, err := purl.PackageKey(k.Package)
	if err != nil {
		return SuppressionKey{}, fmt.Errorf("package %q is not a purl: %w", k.Package, ErrInvalid)
	}
	ids, err := vulnerabilityIDs(ctx, q, k.VulnerabilityID)
	if err != nil {
		return SuppressionKey{}, err
	}
	switch len(ids) {
	case 0:
		return SuppressionKey{}, fmt.Errorf("unknown vulnerability %q: %w", k.VulnerabilityID, ErrInvalid)
	case 1:
	default:
		return SuppressionKey{}, fmt.Errorf("%q names several vulnerabilities (%s): %w",
			k.VulnerabilityID, strings.Join(ids, ", "), ErrInvalid)
	}
	k.Package, k.VulnerabilityID = pkg, ids[0]
	return k, nil
}

// SetSuppressions sets team's suppressions, replacing any with the same key, in one
// transaction: all of them or none. It returns them as stored.
func (db *DB) SetSuppressions(ctx context.Context, team string, items []NewSuppression, actor string) ([]Suppression, error) {
	switch {
	case team == "":
		return nil, fmt.Errorf("team is required: %w", ErrInvalid)
	case actor == "":
		return nil, fmt.Errorf("actor is required: %w", ErrInvalid)
	case len(items) == 0:
		return nil, fmt.Errorf("no suppressions: %w", ErrInvalid)
	}

	var set []Suppression
	err := pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		if err := enableSuppressionEvents(ctx, tx, actor); err != nil {
			return err
		}
		seen := make(map[SuppressionKey]int, len(items))
		for i, item := range items {
			if err := item.validate(); err != nil {
				return fmt.Errorf("suppression %d: %w", i, err)
			}
			key, err := item.canonical(ctx, tx)
			if err != nil {
				return fmt.Errorf("suppression %d: %w", i, err)
			}
			if j, ok := seen[key]; ok {
				return fmt.Errorf("suppression %d: same workload, image, package and vulnerability as suppression %d: %w", i, j, ErrInvalid)
			}
			seen[key] = i

			rows, err := tx.Query(ctx, `
				INSERT INTO suppressions AS s (team, environment, workload, image_name, package_key, vulnerability_id, state, detail, updated_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
				ON CONFLICT (team, environment, workload, image_name, package_key, vulnerability_id) DO UPDATE
				SET state = excluded.state, detail = excluded.detail, updated_by = excluded.updated_by,
					updated_at = now()
				RETURNING `+suppressionColumns,
				team, key.Environment, key.Workload, key.ImageName, key.Package, key.VulnerabilityID, item.State, item.Detail, actor)
			if err != nil {
				return fmt.Errorf("suppression %d: %w", i, err)
			}
			s, err := pgx.CollectExactlyOneRow(rows, collectSuppression)
			if err != nil {
				return fmt.Errorf("suppression %d: %w", i, err)
			}
			set = append(set, s)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return set, nil
}

// DeleteSuppressions deletes team's suppressions with keys, in one transaction, and
// returns the ones that existed. Deleting a suppression that does not exist is not an error.
func (db *DB) DeleteSuppressions(ctx context.Context, team string, keys []SuppressionKey) ([]Suppression, error) {
	return db.DeleteSuppressionsAs(ctx, team, keys, "")
}

func (db *DB) DeleteSuppressionsAs(ctx context.Context, team string, keys []SuppressionKey, actor string) ([]Suppression, error) {
	switch {
	case team == "":
		return nil, fmt.Errorf("team is required: %w", ErrInvalid)
	case len(keys) == 0:
		return nil, fmt.Errorf("no suppressions: %w", ErrInvalid)
	}

	var deleted []Suppression
	err := pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		if err := enableSuppressionEvents(ctx, tx, actor); err != nil {
			return err
		}
		for i, k := range keys {
			key, err := k.canonical(ctx, tx)
			if err != nil {
				return fmt.Errorf("suppression %d: %w", i, err)
			}
			rows, err := tx.Query(ctx, `
				DELETE FROM suppressions s
				WHERE s.team = $1 AND s.environment = $2 AND s.workload = $3
					AND s.image_name = $4 AND s.package_key = $5 AND s.vulnerability_id = $6
				RETURNING `+suppressionColumns,
				team, key.Environment, key.Workload, key.ImageName, key.Package, key.VulnerabilityID)
			if err != nil {
				return fmt.Errorf("suppression %d: %w", i, err)
			}
			s, err := pgx.CollectExactlyOneRow(rows, collectSuppression)
			if errors.Is(err, pgx.ErrNoRows) {
				continue
			}
			if err != nil {
				return fmt.Errorf("suppression %d: %w", i, err)
			}
			deleted = append(deleted, s)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return deleted, nil
}

// SuppressionFilter narrows suppressions. Empty fields do not filter.
type SuppressionFilter struct {
	Teams           []string
	Environment     string
	Workload        string
	ImageName       string
	VulnerabilityID string // ID or alias
}

type suppressionCursor struct {
	Team            string `json:"t"`
	Environment     string `json:"e"`
	Workload        string `json:"w"`
	ImageName       string `json:"i"`
	PackageKey      string `json:"p"`
	VulnerabilityID string `json:"v"`
}

// PageToken returns a cursor immediately after this suppression.
func (s Suppression) PageToken() (string, error) {
	return encodePageToken(suppressionCursor{s.Team, s.Environment, s.Workload, s.ImageName, s.Package, s.VulnerabilityID})
}

// ListSuppressions lists suppressions matching filter, ordered by key.
func (db *DB) ListSuppressions(ctx context.Context, filter SuppressionFilter, page Page) ([]Suppression, string, error) {
	var cursor suppressionCursor
	if err := decodePageToken(page.Token, &cursor); err != nil {
		return nil, "", err
	}
	if page.Token != "" && (cursor.Environment == "" || cursor.Workload == "") {
		return nil, "", fmt.Errorf("page token predates workload-scoped suppressions: %w", ErrInvalid)
	}
	var (
		args  sqlArgs
		where []string
	)
	if len(filter.Teams) > 0 {
		where = append(where, "s.team = ANY("+args.add(filter.Teams)+")")
	}
	if filter.Environment != "" {
		where = append(where, "s.environment = "+args.add(filter.Environment))
	}
	if filter.Workload != "" {
		where = append(where, "s.workload = "+args.add(filter.Workload))
	}
	if filter.ImageName != "" {
		where = append(where, "s.image_name = "+args.add(filter.ImageName))
	}
	if filter.VulnerabilityID != "" {
		where = append(where, vulnerabilityMatch("s.vulnerability_id", filter.VulnerabilityID, &args))
	}
	if page.Token != "" {
		where = append(where, fmt.Sprintf("(s.team, s.environment, s.workload, s.image_name, s.package_key, s.vulnerability_id) > (%s, %s, %s, %s, %s, %s)",
			args.add(cursor.Team), args.add(cursor.Environment), args.add(cursor.Workload), args.add(cursor.ImageName), args.add(cursor.PackageKey), args.add(cursor.VulnerabilityID)))
	}
	limit := page.limit()

	rows, err := db.pool.Query(ctx, `
		SELECT `+suppressionColumns+`
		FROM suppressions s
		WHERE `+and(where)+`
		ORDER BY s.team, s.environment, s.workload, s.image_name, s.package_key, s.vulnerability_id
		LIMIT `+args.add(limit+1), args...)
	if err != nil {
		return nil, "", fmt.Errorf("listing suppressions: %w", err)
	}
	suppressions, err := pgx.CollectRows(rows, collectSuppression)
	if err != nil {
		return nil, "", fmt.Errorf("listing suppressions: %w", err)
	}

	var next string
	if len(suppressions) > limit {
		suppressions = suppressions[:limit]
		next, err = suppressions[limit-1].PageToken()
		if err != nil {
			return nil, "", err
		}
	}
	return suppressions, next, nil
}
