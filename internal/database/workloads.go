package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s"
)

// clusterLockSpace is the first key of the two-key advisory locks that serialize
// SyncWorkloadImages per cluster.
const clusterLockSpace = 0x7630_7343 // "v0sC"

// SyncWorkloadImages makes ws the complete set of workload images for cluster. It creates
// missing images (sbom_state pending), bumps last_seen_at for every image in ws, and replaces
// the cluster's workload_images rows. Atomic.
//
// Every element of ws must have Cluster equal to cluster.
func (db *DB) SyncWorkloadImages(ctx context.Context, cluster string, ws []v0s.WorkloadImage) error {
	var namespaces, workloads, containers, ownerKinds, names, digests []string
	for _, w := range ws {
		if w.Cluster != cluster {
			return fmt.Errorf("workload image %s/%s in cluster %q, want %q", w.Namespace, w.Workload, w.Cluster, cluster)
		}
		namespaces = append(namespaces, w.Namespace)
		workloads = append(workloads, w.Workload)
		containers = append(containers, w.Container)
		ownerKinds = append(ownerKinds, w.OwnerKind)
		names = append(names, w.ImageName)
		digests = append(digests, w.Digest)
	}

	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		// Concurrent syncs of one cluster would each delete before the other inserts, leaving
		// the union of both snapshots, so they take turns.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`, clusterLockSpace, cluster); err != nil {
			return fmt.Errorf("locking cluster %q: %w", cluster, err)
		}

		// Rows are upserted in a fixed order so that concurrent syncs of clusters
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

		if _, err := tx.Exec(ctx, `DELETE FROM workload_images WHERE cluster = $1`, cluster); err != nil {
			return fmt.Errorf("deleting workload images: %w", err)
		}

		// Replicas of a workload report the same container and image, hence ON CONFLICT.
		if _, err := tx.Exec(ctx, `
			INSERT INTO workload_images (cluster, namespace, workload, container, image_id, owner_kind)
			SELECT $1, t.namespace, t.workload, t.container, i.id, t.owner_kind
			FROM unnest($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[])
				AS t (namespace, workload, container, owner_kind, name, digest)
			JOIN images i ON i.name = t.name AND i.digest = t.digest
			ON CONFLICT DO NOTHING`,
			cluster, namespaces, workloads, containers, ownerKinds, names, digests,
		); err != nil {
			return fmt.Errorf("inserting workload images: %w", err)
		}
		return nil
	})
}
