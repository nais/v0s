package database

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s/internal/purl"
)

type ForwardOutcome int

const (
	ForwardApplied ForwardOutcome = iota + 1
	ForwardNoWorkloads
	ForwardUnknownVulnerability
	ForwardAmbiguousVulnerability
)

type V13sSuppression struct {
	ImageName        string
	Package          string
	VulnerabilityIDs []string
	Assessment       *V13sAssessment
}

type V13sAssessment struct {
	State     string
	Detail    string
	UpdatedBy string
	UpdatedAt time.Time
}

type ForwardResult struct {
	Outcome ForwardOutcome
	Applied int
	Removed int
}

func (s V13sSuppression) validate() error {
	switch {
	case s.ImageName == "":
		return fmt.Errorf("image name is required: %w", ErrInvalid)
	case len(s.VulnerabilityIDs) == 0 || slices.Contains(s.VulnerabilityIDs, ""):
		return fmt.Errorf("vulnerability IDs are required and must not be empty: %w", ErrInvalid)
	case s.Assessment == nil:
		return nil
	case s.Assessment.UpdatedBy == "":
		return fmt.Errorf("actor is required: %w", ErrInvalid)
	case s.Assessment.UpdatedAt.IsZero():
		return fmt.Errorf("update time is required: %w", ErrInvalid)
	}
	return NewSuppression{State: s.Assessment.State, Detail: s.Assessment.Detail}.validate()
}

func (db *DB) ApplyV13sSuppression(ctx context.Context, s V13sSuppression) (ForwardResult, error) {
	if err := s.validate(); err != nil {
		return ForwardResult{}, err
	}
	pkg, err := purl.PackageKey(s.Package)
	if err != nil {
		return ForwardResult{}, fmt.Errorf("package %q is not a purl: %w", s.Package, ErrInvalid)
	}

	var result ForwardResult
	err = pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id FROM vulnerabilities WHERE id = ANY($1)
			UNION
			SELECT vulnerability_id FROM vulnerability_aliases WHERE alias = ANY($1)`, s.VulnerabilityIDs)
		if err != nil {
			return fmt.Errorf("resolving vulnerability: %w", err)
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return fmt.Errorf("resolving vulnerability: %w", err)
		}
		switch len(ids) {
		case 0:
			result.Outcome = ForwardUnknownVulnerability
			return nil
		case 1:
		default:
			result.Outcome = ForwardAmbiguousVulnerability
			return nil
		}

		if s.Assessment == nil {
			tag, err := tx.Exec(ctx, `
				DELETE FROM suppressions
				WHERE image_name = $1 AND package_key = $2 AND vulnerability_id = $3`,
				s.ImageName, pkg, ids[0])
			if err != nil {
				return fmt.Errorf("deleting suppressions: %w", err)
			}
			result.Outcome, result.Removed = ForwardApplied, int(tag.RowsAffected())
			return nil
		}

		var workloads int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM workloads w JOIN images i ON i.id = w.image_id WHERE i.name = $1`,
			s.ImageName).Scan(&workloads); err != nil {
			return fmt.Errorf("counting workloads: %w", err)
		}
		if workloads == 0 {
			result.Outcome = ForwardNoWorkloads
			return nil
		}
		a := s.Assessment
		tag, err := tx.Exec(ctx, `
			INSERT INTO suppressions AS s (team, environment, workload, image_name, package_key, vulnerability_id, state, detail, updated_by, updated_at)
			SELECT w.team, w.environment, w.name, i.name, $2, $3, $4, $5, $6, $7
			FROM workloads w JOIN images i ON i.id = w.image_id
			WHERE i.name = $1
			ON CONFLICT (team, environment, workload, image_name, package_key, vulnerability_id) DO UPDATE
			SET state = excluded.state, detail = excluded.detail, updated_by = excluded.updated_by,
				updated_at = excluded.updated_at
			WHERE s.updated_at < excluded.updated_at`,
			s.ImageName, pkg, ids[0], a.State, a.Detail, a.UpdatedBy, a.UpdatedAt)
		if err != nil {
			return fmt.Errorf("setting suppressions: %w", err)
		}
		result.Outcome, result.Applied = ForwardApplied, int(tag.RowsAffected())
		return nil
	})
	if err != nil {
		return ForwardResult{}, err
	}
	return result, nil
}
