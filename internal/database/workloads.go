package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s"
)

// SyncWorkloadImages makes ws the complete set of workloads for environment. It creates missing
// images (sbom_state pending) and replaces the environment's workloads, atomically. Images no
// longer used are left for DeleteUnusedImages. Syncs must not run concurrently.
//
// Every element of ws must have Environment equal to environment. A workload listed twice
// must be listed the same way both times.
func (db *DB) SyncWorkloadImages(ctx context.Context, environment string, ws []v0s.WorkloadImage) error {
	type key struct{ team, workload string }
	seen := make(map[key]v0s.WorkloadImage, len(ws))
	var teams, workloads, refs, names, digests, errs []string
	for _, w := range ws {
		if w.Environment != environment {
			return fmt.Errorf("workload %s/%s in environment %q, want %q", w.Team, w.Workload, w.Environment, environment)
		}
		k := key{w.Team, w.Workload}
		if prev, ok := seen[k]; ok {
			if prev != w {
				return fmt.Errorf("workload %s/%s listed with images %s and %s", w.Team, w.Workload, prev.Reference, w.Reference)
			}
			continue
		}
		seen[k] = w
		teams = append(teams, w.Team)
		workloads = append(workloads, w.Workload)
		refs = append(refs, w.Reference)
		names = append(names, w.ImageName)
		digests = append(digests, w.Digest)
		errs = append(errs, w.ResolveError)
	}

	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO images (name, digest)
			SELECT DISTINCT name, digest FROM unnest($1::text[], $2::text[]) AS t (name, digest)
			WHERE digest <> ''
			ON CONFLICT (name, digest) DO NOTHING`,
			names, digests,
		); err != nil {
			return fmt.Errorf("inserting images: %w", err)
		}

		if _, err := tx.Exec(ctx, `DELETE FROM workloads WHERE environment = $1`, environment); err != nil {
			return fmt.Errorf("deleting workloads: %w", err)
		}

		if _, err := tx.Exec(ctx, `
			INSERT INTO workloads (environment, team, name, image_reference, image_id, resolve_error)
			SELECT $1, t.team, t.workload, t.ref, i.id, t.err
			FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[])
				AS t (team, workload, ref, name, digest, err)
			LEFT JOIN images i ON i.name = t.name AND i.digest = t.digest`,
			environment, teams, workloads, refs, names, digests, errs,
		); err != nil {
			return fmt.Errorf("inserting workloads: %w", err)
		}
		return nil
	})
}

// Workload is a workload and the image it is deployed with.
type Workload struct {
	Environment    string
	Team           string
	Name           string
	ImageReference string
	// Image is nil if ImageReference could not be resolved, and ResolveError says why.
	Image        *v0s.Image
	ResolveError string
}

// WorkloadFilter narrows workloads. Empty fields do not filter.
type WorkloadFilter struct {
	Teams       []string
	Environment string
}

type workloadCursor struct {
	Environment string `json:"e"`
	Team        string `json:"t"`
	Name        string `json:"w"`
}

// ListWorkloads lists workloads ordered by environment, team and name.
func (db *DB) ListWorkloads(ctx context.Context, filter WorkloadFilter, page Page) ([]Workload, string, error) {
	var cursor workloadCursor
	if err := decodePageToken(page.Token, &cursor); err != nil {
		return nil, "", err
	}
	var (
		args  sqlArgs
		where []string
	)
	if len(filter.Teams) > 0 {
		where = append(where, "w.team = ANY("+args.add(filter.Teams)+")")
	}
	if filter.Environment != "" {
		where = append(where, "w.environment = "+args.add(filter.Environment))
	}
	if page.Token != "" {
		where = append(where, fmt.Sprintf("(w.environment, w.team, w.name) > (%s, %s, %s)",
			args.add(cursor.Environment), args.add(cursor.Team), args.add(cursor.Name)))
	}
	limit := page.limit()

	rows, err := db.pool.Query(ctx, `
		SELECT w.environment, w.team, w.name, w.image_reference, w.resolve_error, `+imageColumns+`
		FROM workloads w
		LEFT JOIN images i ON i.id = w.image_id
		WHERE `+and(where)+`
		ORDER BY w.environment, w.team, w.name
		LIMIT `+args.add(limit+1), args...)
	if err != nil {
		return nil, "", fmt.Errorf("listing workloads: %w", err)
	}
	workloads, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Workload, error) {
		var (
			w   Workload
			img imageScan
		)
		err := row.Scan(append([]any{&w.Environment, &w.Team, &w.Name, &w.ImageReference, &w.ResolveError}, img.dest()...)...)
		if img.found() {
			i := img.image()
			w.Image = &i
		}
		return w, err
	})
	if err != nil {
		return nil, "", fmt.Errorf("listing workloads: %w", err)
	}

	var next string
	if len(workloads) > limit {
		workloads = workloads[:limit]
		last := workloads[limit-1]
		next, err = encodePageToken(workloadCursor{Environment: last.Environment, Team: last.Team, Name: last.Name})
		if err != nil {
			return nil, "", err
		}
	}
	return workloads, next, nil
}
