package database

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v0s/internal/purl"
)

// Suppression is a team's assessment that a vulnerability does not apply to a
// package in an image name, in the team's own workloads. It is active when not
// revoked and not expired.
type Suppression struct {
	ID              int64
	Team            string
	ImageName       string
	PackageKey      string
	VulnerabilityID string
	State           string // not_affected, false_positive or accepted_risk
	Justification   string // CycloneDX/VEX justification, set only for not_affected
	Detail          string
	CreatedBy       string
	CreatedAt       time.Time
	ExpiresAt       time.Time // zero if it never expires
	RevokedAt       time.Time // zero if not revoked
	RevokedBy       string
	RevokeReason    string
}

// suppressionColumns are the columns of suppressions s that suppressionScan reads.
const suppressionColumns = `s.id, s.team, s.image_name, s.package_key, s.vulnerability_id, s.state, s.justification, s.detail,
	s.created_by, s.created_at, s.expires_at, s.revoked_at, s.revoked_by, s.revoke_reason`

// suppressionScan reads suppressionColumns.
type suppressionScan struct {
	id                                                        int64
	team, imageName, packageKey, vulnerabilityID, state       string
	justification, detail, createdBy, revokedBy, revokeReason string
	createdAt                                                 time.Time
	expiresAt, revokedAt                                      pgtype.Timestamptz
}

func (s *suppressionScan) dest() []any {
	return []any{&s.id, &s.team, &s.imageName, &s.packageKey, &s.vulnerabilityID, &s.state, &s.justification, &s.detail,
		&s.createdBy, &s.createdAt, &s.expiresAt, &s.revokedAt, &s.revokedBy, &s.revokeReason}
}

func (s *suppressionScan) suppression() Suppression {
	return Suppression{
		ID:              s.id,
		Team:            s.team,
		ImageName:       s.imageName,
		PackageKey:      s.packageKey,
		VulnerabilityID: s.vulnerabilityID,
		State:           s.state,
		Justification:   s.justification,
		Detail:          s.detail,
		CreatedBy:       s.createdBy,
		CreatedAt:       s.createdAt,
		ExpiresAt:       s.expiresAt.Time,
		RevokedAt:       s.revokedAt.Time,
		RevokedBy:       s.revokedBy,
		RevokeReason:    s.revokeReason,
	}
}

func scanSuppression(row pgx.Row) (Suppression, error) {
	var s suppressionScan
	if err := row.Scan(s.dest()...); err != nil {
		return Suppression{}, err
	}
	return s.suppression(), nil
}

func collectSuppression(row pgx.CollectableRow) (Suppression, error) { return scanSuppression(row) }

// NewSuppression is a suppression to create.
type NewSuppression struct {
	ImageName       string
	Package         string // package key or purl; version, qualifiers and subpath are dropped
	VulnerabilityID string // ID or alias, must name exactly one vulnerability
	State           string // not_affected, false_positive or accepted_risk
	Justification   string // required for not_affected, empty otherwise
	Detail          string
	ExpiresAt       time.Time // zero if it never expires
}

// CreatedSuppression is the result of creating one suppression.
type CreatedSuppression struct {
	Suppression     Suppression
	MatchedFindings int64 // current findings on images the team uses that the suppression matches
	ReplacesID      int64 // the active suppression this one replaced, 0 if none
}

func validState(state string) bool {
	switch state {
	case "not_affected", "false_positive", "accepted_risk":
		return true
	}
	return false
}

func validJustification(justification string) bool {
	switch justification {
	case "code_not_present", "code_not_reachable", "requires_configuration", "requires_dependency",
		"requires_environment", "protected_by_compiler", "protected_at_runtime", "protected_at_perimeter",
		"protected_by_mitigating_control":
		return true
	}
	return false
}

func (n NewSuppression) validate(now time.Time) error {
	switch {
	case n.ImageName == "":
		return fmt.Errorf("image name is required: %w", ErrInvalid)
	case n.VulnerabilityID == "":
		return fmt.Errorf("vulnerability ID is required: %w", ErrInvalid)
	case !validState(n.State):
		return fmt.Errorf("invalid state %q: %w", n.State, ErrInvalid)
	case n.State == "not_affected" && n.Justification == "":
		return fmt.Errorf("justification is required for not_affected: %w", ErrInvalid)
	case n.State != "not_affected" && n.Justification != "":
		return fmt.Errorf("justification is only allowed for not_affected: %w", ErrInvalid)
	case n.Justification != "" && !validJustification(n.Justification):
		return fmt.Errorf("invalid justification %q: %w", n.Justification, ErrInvalid)
	case n.Detail == "":
		return fmt.Errorf("detail is required: %w", ErrInvalid)
	case !n.ExpiresAt.IsZero() && !n.ExpiresAt.After(now):
		return fmt.Errorf("expiry must be in the future: %w", ErrInvalid)
	}
	return nil
}

// CreateSuppressions creates suppressions for team in one transaction: all of them or none.
//
// Creating a suppression revokes the team's unrevoked suppression with the same key,
// if any. An active predecessor is revoked as "replaced by suppression <id>",
// an expired one as "expired". With dryRun everything is rolled back, and the
// results have ID 0.
func (db *DB) CreateSuppressions(ctx context.Context, team string, items []NewSuppression, actor string, dryRun bool) ([]CreatedSuppression, error) {
	switch {
	case team == "":
		return nil, fmt.Errorf("team is required: %w", ErrInvalid)
	case actor == "":
		return nil, fmt.Errorf("actor is required: %w", ErrInvalid)
	}
	now := time.Now()

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	type key struct{ image, pkg, vuln string }
	seen := make(map[key]int, len(items))
	results := make([]CreatedSuppression, 0, len(items))
	for i, item := range items {
		if err := item.validate(now); err != nil {
			return nil, fmt.Errorf("suppression %d: %w", i, err)
		}
		pkg, err := purl.PackageKey(item.Package)
		if err != nil {
			return nil, fmt.Errorf("suppression %d: package %q is not a purl: %w", i, item.Package, ErrInvalid)
		}
		ids, err := vulnerabilityIDs(ctx, tx, item.VulnerabilityID)
		if err != nil {
			return nil, err
		}
		switch len(ids) {
		case 0:
			return nil, fmt.Errorf("suppression %d: unknown vulnerability %q: %w", i, item.VulnerabilityID, ErrInvalid)
		case 1:
		default:
			return nil, fmt.Errorf("suppression %d: %q names several vulnerabilities (%s): %w",
				i, item.VulnerabilityID, strings.Join(ids, ", "), ErrInvalid)
		}
		k := key{item.ImageName, pkg, ids[0]}
		if j, ok := seen[k]; ok {
			return nil, fmt.Errorf("suppression %d: same image, package and vulnerability as suppression %d: %w", i, j, ErrInvalid)
		}
		seen[k] = i

		s := Suppression{
			Team:            team,
			ImageName:       item.ImageName,
			PackageKey:      pkg,
			VulnerabilityID: ids[0],
			State:           item.State,
			Justification:   item.Justification,
			Detail:          item.Detail,
			CreatedBy:       actor,
			ExpiresAt:       item.ExpiresAt,
		}
		created, err := createSuppression(ctx, tx, s)
		if err != nil {
			return nil, fmt.Errorf("suppression %d: %w", i, err)
		}
		results = append(results, created)
	}

	if dryRun {
		for i := range results {
			results[i].Suppression.ID = 0
		}
		return results, nil
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing suppressions: %w", err)
	}
	return results, nil
}

// createSuppression revokes the unrevoked suppression with the same key as s, inserts s and counts its matches.
func createSuppression(ctx context.Context, tx pgx.Tx, s Suppression) (CreatedSuppression, error) {
	var (
		previousID      int64
		previousExpired bool
	)
	err := tx.QueryRow(ctx, `
		SELECT id, expires_at IS NOT NULL AND expires_at <= now()
		FROM suppressions
		WHERE team = $1 AND image_name = $2 AND package_key = $3 AND vulnerability_id = $4 AND revoked_at IS NULL
		FOR UPDATE`, s.Team, s.ImageName, s.PackageKey, s.VulnerabilityID).Scan(&previousID, &previousExpired)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return CreatedSuppression{}, fmt.Errorf("finding previous suppression: %w", err)
	}

	// Take the ID first, so the predecessor's revoke reason can name it.
	if err := tx.QueryRow(ctx, "SELECT nextval(pg_get_serial_sequence('suppressions', 'id'))").Scan(&s.ID); err != nil {
		return CreatedSuppression{}, fmt.Errorf("allocating suppression ID: %w", err)
	}

	created := CreatedSuppression{}
	if previousID != 0 {
		reason := "replaced by suppression " + strconv.FormatInt(s.ID, 10)
		if previousExpired {
			reason = "expired"
		} else {
			created.ReplacesID = previousID
		}
		_, err := tx.Exec(ctx, "UPDATE suppressions SET revoked_at = now(), revoked_by = $2, revoke_reason = $3 WHERE id = $1",
			previousID, s.CreatedBy, reason)
		if err != nil {
			return CreatedSuppression{}, fmt.Errorf("revoking previous suppression: %w", err)
		}
	}

	var expiresAt *time.Time
	if !s.ExpiresAt.IsZero() {
		expiresAt = &s.ExpiresAt
	}
	err = tx.QueryRow(ctx, `
		INSERT INTO suppressions (id, team, image_name, package_key, vulnerability_id, state, justification, detail, created_by, expires_at)
		OVERRIDING SYSTEM VALUE
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING created_at`,
		s.ID, s.Team, s.ImageName, s.PackageKey, s.VulnerabilityID, s.State, s.Justification, s.Detail, s.CreatedBy, expiresAt,
	).Scan(&s.CreatedAt)
	if pgErr := (*pgconn.PgError)(nil); errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return CreatedSuppression{}, fmt.Errorf("suppression was created concurrently: %w", ErrConflict)
	}
	if err != nil {
		return CreatedSuppression{}, fmt.Errorf("inserting suppression: %w", err)
	}
	created.Suppression = s

	err = tx.QueryRow(ctx, `
		SELECT count(*)
		FROM findings f JOIN images i ON i.id = f.image_id
		WHERE i.name = $2 AND f.package_key = $3 AND f.vulnerability_id = $4
			AND EXISTS (SELECT 1 FROM workloads w WHERE w.image_id = i.id AND w.team = $1)`,
		s.Team, s.ImageName, s.PackageKey, s.VulnerabilityID).Scan(&created.MatchedFindings)
	if err != nil {
		return CreatedSuppression{}, fmt.Errorf("counting matched findings: %w", err)
	}
	return created, nil
}

// RevokeSuppressions revokes team's suppressions in one transaction: all of them or
// none. An unknown ID, or one of another team, is ErrNotFound; a revoked one ErrAlreadyRevoked.
func (db *DB) RevokeSuppressions(ctx context.Context, team string, ids []int64, actor, reason string) ([]Suppression, error) {
	switch {
	case team == "":
		return nil, fmt.Errorf("team is required: %w", ErrInvalid)
	case len(ids) == 0:
		return nil, fmt.Errorf("no suppression IDs: %w", ErrInvalid)
	case actor == "":
		return nil, fmt.Errorf("actor is required: %w", ErrInvalid)
	case reason == "":
		return nil, fmt.Errorf("reason is required: %w", ErrInvalid)
	}

	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	revoked := make([]Suppression, 0, len(ids))
	for _, id := range ids {
		s, err := scanSuppression(tx.QueryRow(ctx, `
			UPDATE suppressions s SET revoked_at = now(), revoked_by = $3, revoke_reason = $4
			WHERE s.id = $1 AND s.team = $2 AND s.revoked_at IS NULL
			RETURNING `+suppressionColumns, id, team, actor, reason))
		if errors.Is(err, pgx.ErrNoRows) {
			var exists bool
			if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM suppressions WHERE id = $1 AND team = $2)", id, team).Scan(&exists); err != nil {
				return nil, fmt.Errorf("revoking suppression %d: %w", id, err)
			}
			if exists {
				return nil, fmt.Errorf("suppression %d: %w", id, ErrAlreadyRevoked)
			}
			return nil, fmt.Errorf("suppression %d: %w", id, ErrNotFound)
		}
		if err != nil {
			return nil, fmt.Errorf("revoking suppression %d: %w", id, err)
		}
		revoked = append(revoked, s)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("committing revocations: %w", err)
	}
	return revoked, nil
}

// SuppressionFilter narrows suppressions. Empty fields do not filter.
type SuppressionFilter struct {
	Teams           []string
	ImageName       string
	VulnerabilityID string // ID or alias
	IncludeInactive bool   // include revoked and expired suppressions
}

// ListSuppressions lists suppressions matching filter, ordered by ID.
func (db *DB) ListSuppressions(ctx context.Context, filter SuppressionFilter, page Page) ([]Suppression, string, error) {
	var cursor struct {
		ID int64 `json:"id"`
	}
	if err := decodePageToken(page.Token, &cursor); err != nil {
		return nil, "", err
	}
	var (
		args  sqlArgs
		where = []string{"s.id > " + args.add(cursor.ID)}
	)
	if len(filter.Teams) > 0 {
		where = append(where, "s.team = ANY("+args.add(filter.Teams)+")")
	}
	if filter.ImageName != "" {
		where = append(where, "s.image_name = "+args.add(filter.ImageName))
	}
	if filter.VulnerabilityID != "" {
		where = append(where, vulnerabilityMatch("s.vulnerability_id", filter.VulnerabilityID, &args))
	}
	if !filter.IncludeInactive {
		where = append(where, "s.revoked_at IS NULL AND (s.expires_at IS NULL OR s.expires_at > now())")
	}
	limit := page.limit()

	rows, err := db.pool.Query(ctx, `
		SELECT `+suppressionColumns+`
		FROM suppressions s
		WHERE `+and(where)+`
		ORDER BY s.id
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
		cursor.ID = suppressions[limit-1].ID
		if next, err = encodePageToken(cursor); err != nil {
			return nil, "", err
		}
	}
	return suppressions, next, nil
}
