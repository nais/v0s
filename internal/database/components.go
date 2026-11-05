package database

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s"
)

// ComponentMatch is a component in the SBOM of an image in use.
type ComponentMatch struct {
	Component v0s.Component
	Image     v0s.Image
	Workloads []WorkloadRef // workloads using the image, limited to the requested teams
}

// WorkloadRef identifies a workload.
type WorkloadRef struct {
	Environment string
	Team        string
	Name        string
}

// ComponentFilter selects components.
type ComponentFilter struct {
	// Query is a package key, a purl with version for an exact match, or,
	// when it does not start with "pkg:", a case-insensitive name prefix.
	Query string
	Teams []string // only images used by these teams; empty for all
}

type componentCursor struct {
	ImageID int64  `json:"i"`
	PURL    string `json:"p"`
}

// SearchComponents finds components in SBOMs of images in use, with or
// without findings, ordered by image and purl.
func (db *DB) SearchComponents(ctx context.Context, filter ComponentFilter, page Page) ([]ComponentMatch, string, error) {
	if filter.Query == "" {
		return nil, "", fmt.Errorf("query is required: %w", ErrInvalid)
	}
	var cursor componentCursor
	if err := decodePageToken(page.Token, &cursor); err != nil {
		return nil, "", err
	}

	var (
		args     sqlArgs
		where    []string
		workload []string
	)
	if strings.HasPrefix(filter.Query, "pkg:") {
		cond, err := packageMatch("c.purl", "c.package_key", filter.Query, &args)
		if err != nil {
			return nil, "", err
		}
		where = append(where, cond)
	} else {
		where = append(where, "lower(c.name) LIKE "+args.add(likePrefix(strings.ToLower(filter.Query))))
	}
	if len(filter.Teams) > 0 {
		workload = append(workload, "wi.team = ANY("+args.add(filter.Teams)+")")
	}
	where = append(where, inUse(workload))
	if page.Token != "" {
		where = append(where, fmt.Sprintf("(c.image_id, c.purl) > (%s, %s)", args.add(cursor.ImageID), args.add(cursor.PURL)))
	}
	limit := page.limit()

	rows, err := db.pool.Query(ctx, `
		SELECT c.purl, c.package_key, c.name, c.version, `+imageColumns+`
		FROM components c
		JOIN images i ON i.id = c.image_id
		WHERE `+and(where)+`
		ORDER BY c.image_id, c.purl
		LIMIT `+args.add(limit+1), args...)
	if err != nil {
		return nil, "", fmt.Errorf("searching components: %w", err)
	}
	matches, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ComponentMatch, error) {
		var (
			m   ComponentMatch
			img imageScan
		)
		err := row.Scan(append([]any{&m.Component.PURL, &m.Component.PackageKey, &m.Component.Name, &m.Component.Version}, img.dest()...)...)
		m.Image = img.image()
		return m, err
	})
	if err != nil {
		return nil, "", fmt.Errorf("searching components: %w", err)
	}

	var next string
	if len(matches) > limit {
		matches = matches[:limit]
		last := matches[limit-1]
		if next, err = encodePageToken(componentCursor{ImageID: last.Image.ID, PURL: last.Component.PURL}); err != nil {
			return nil, "", err
		}
	}
	if len(matches) == 0 {
		return nil, "", nil
	}

	imageIDs := make([]int64, 0, len(matches))
	for _, m := range matches {
		imageIDs = append(imageIDs, m.Image.ID)
	}
	args = nil
	where = []string{"image_id = ANY(" + args.add(imageIDs) + ")"}
	if len(filter.Teams) > 0 {
		where = append(where, "team = ANY("+args.add(filter.Teams)+")")
	}
	rows, err = db.pool.Query(ctx, `
		SELECT image_id, environment, team, workload
		FROM workload_images
		WHERE `+and(where)+`
		ORDER BY image_id, environment, team, workload`, args...)
	if err != nil {
		return nil, "", fmt.Errorf("listing component workloads: %w", err)
	}
	workloads := make(map[int64][]WorkloadRef)
	var (
		imageID int64
		ref     WorkloadRef
	)
	_, err = pgx.ForEachRow(rows, []any{&imageID, &ref.Environment, &ref.Team, &ref.Name}, func() error {
		workloads[imageID] = append(workloads[imageID], ref)
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("listing component workloads: %w", err)
	}
	for i := range matches {
		matches[i].Workloads = workloads[matches[i].Image.ID]
	}
	return matches, next, nil
}

// likePrefix returns a LIKE pattern matching strings that start with s.
func likePrefix(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s) + "%"
}
