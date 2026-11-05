package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s"
)

// environmentLockSpace is the first key of the two-key advisory locks that serialize
// SyncWorkloadImages per environment.
const environmentLockSpace = 0x7630_7345 // "v0sE"

// SyncWorkloadImages makes ws the complete set of workload images for environment. It creates
// missing images (sbom_state pending), bumps last_seen_at for every image in ws, and replaces
// the environment's workload_images rows. Atomic.
//
// Every element of ws must have Environment equal to environment.
func (db *DB) SyncWorkloadImages(ctx context.Context, environment string, ws []v0s.WorkloadImage) error {
	var teams, workloads, names, digests []string
	for _, w := range ws {
		if w.Environment != environment {
			return fmt.Errorf("workload image %s/%s in environment %q, want %q", w.Team, w.Workload, w.Environment, environment)
		}
		teams = append(teams, w.Team)
		workloads = append(workloads, w.Workload)
		names = append(names, w.ImageName)
		digests = append(digests, w.Digest)
	}

	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		// Concurrent syncs of one environment would each delete before the other inserts, leaving
		// the union of both snapshots, so they take turns.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`, environmentLockSpace, environment); err != nil {
			return fmt.Errorf("locking environment %q: %w", environment, err)
		}

		// Rows are upserted in a fixed order so that concurrent syncs of environments
		// sharing images lock them in the same order.
		if _, err := tx.Exec(ctx, `
			INSERT INTO images (name, digest)
			SELECT DISTINCT name, digest FROM unnest($1::text[], $2::text[]) AS t (name, digest)
			ORDER BY name, digest
			ON CONFLICT (name, digest) DO UPDATE SET last_seen_at = now()`,
			names, digests,
		); err != nil {
			return fmt.Errorf("upserting images: %w", err)
		}

		if _, err := tx.Exec(ctx, `DELETE FROM workload_images WHERE environment = $1`, environment); err != nil {
			return fmt.Errorf("deleting workload images: %w", err)
		}

		// Nais API lists a workload once; ON CONFLICT drops a duplicate rather than failing the sync.
		if _, err := tx.Exec(ctx, `
			INSERT INTO workload_images (environment, team, workload, image_id)
			SELECT $1, t.team, t.workload, i.id
			FROM unnest($2::text[], $3::text[], $4::text[], $5::text[]) AS t (team, workload, name, digest)
			JOIN images i ON i.name = t.name AND i.digest = t.digest
			ON CONFLICT DO NOTHING`,
			environment, teams, workloads, names, digests,
		); err != nil {
			return fmt.Errorf("inserting workload images: %w", err)
		}
		return nil
	})
}
