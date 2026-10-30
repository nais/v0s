package database

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s"
)

// imageColumns are the images columns scanned by imageScan, qualified with the alias i.
const imageColumns = `i.id, i.name, i.digest, i.sbom_state, i.sbom_error, i.scanned_at, i.scanned_db_version, i.scan_error`

// ClaimSBOMFetches returns up to limit images that are in use (referenced by workload_images),
// not fetched, and due (sbom_next_attempt_at <= now()). It leases them by moving
// sbom_next_attempt_at to now()+lease. Concurrent callers never get the same image.
func (db *DB) ClaimSBOMFetches(ctx context.Context, limit int, lease time.Duration) ([]v0s.Image, error) {
	rows, err := db.pool.Query(ctx, `
		UPDATE images i SET sbom_next_attempt_at = now() + make_interval(secs => $2)
		WHERE i.id IN (
			SELECT id FROM images
			WHERE sbom_state <> 'fetched'
				AND sbom_next_attempt_at <= now()
				AND EXISTS (SELECT 1 FROM workload_images w WHERE w.image_id = images.id)
			ORDER BY sbom_next_attempt_at
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING `+imageColumns,
		limit, lease.Seconds(),
	)
	if err != nil {
		return nil, fmt.Errorf("claiming sbom fetches: %w", err)
	}
	images, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (v0s.Image, error) {
		var img imageScan
		err := row.Scan(img.dest()...)
		return img.image(), err
	})
	if err != nil {
		return nil, fmt.Errorf("claiming sbom fetches: %w", err)
	}
	return images, nil
}

// StoreSBOM stores the verified SBOM (gzip-compressed) and marks the image fetched. It is
// write-once: if the image's SBOM is already fetched, the stored document is kept, since findings
// and components were derived from it.
func (db *DB) StoreSBOM(ctx context.Context, imageID int64, document []byte) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(document); err != nil {
		return fmt.Errorf("compressing sbom: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("compressing sbom: %w", err)
	}

	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		var state v0s.SBOMState
		err := tx.QueryRow(ctx, `SELECT sbom_state FROM images WHERE id = $1 FOR UPDATE`, imageID).Scan(&state)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("storing sbom: image %d not found", imageID)
		}
		if err != nil {
			return fmt.Errorf("locking image %d: %w", imageID, err)
		}
		if state == v0s.SBOMFetched {
			return nil
		}
		if _, err := tx.Exec(ctx, `
			UPDATE images SET sbom_state = 'fetched', sbom_error = '', sbom_fetched_at = now()
			WHERE id = $1`,
			imageID,
		); err != nil {
			return fmt.Errorf("marking sbom fetched: %w", err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sboms (image_id, document) VALUES ($1, $2)`, imageID, buf.Bytes()); err != nil {
			return fmt.Errorf("storing sbom: %w", err)
		}
		return nil
	})
}

// RecordSBOMFailure marks the image missing or failed with a message and the next attempt time.
// An image whose SBOM has been fetched in the meantime is left alone.
func (db *DB) RecordSBOMFailure(ctx context.Context, imageID int64, state v0s.SBOMState, msg string, retryAt time.Time) error {
	if state != v0s.SBOMMissing && state != v0s.SBOMFailed {
		return fmt.Errorf("recording sbom failure: invalid state %q", state)
	}
	if _, err := db.pool.Exec(ctx, `
		UPDATE images
		SET sbom_state = $2, sbom_error = $3, sbom_next_attempt_at = $4, sbom_attempts = sbom_attempts + 1
		WHERE id = $1 AND sbom_state <> 'fetched'`,
		imageID, string(state), msg, retryAt,
	); err != nil {
		return fmt.Errorf("recording sbom failure: %w", err)
	}
	return nil
}

// DeleteUnusedImages deletes images not referenced by workload_images whose last_seen_at is older
// than unusedFor. Cascades to SBOMs, components and findings. Finding events are kept.
func (db *DB) DeleteUnusedImages(ctx context.Context, unusedFor time.Duration) (int64, error) {
	tag, err := db.pool.Exec(ctx, `
		DELETE FROM images i
		WHERE i.last_seen_at < now() - make_interval(secs => $1)
			AND NOT EXISTS (SELECT 1 FROM workload_images w WHERE w.image_id = i.id)`,
		unusedFor.Seconds(),
	)
	if err != nil {
		return 0, fmt.Errorf("deleting unused images: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ImageStateCount is the number of in-use images in one SBOM state and scan state.
type ImageStateCount struct {
	SBOM v0s.SBOMState
	// Scan is "" if the SBOM is not fetched. Otherwise it is "current" if the image is scanned
	// with the DB version counted against or newer, "failed" if scanning with that version or
	// newer failed, and "pending" if ClaimScan would still claim it.
	Scan  string
	Count int
}

// CountImageStates counts the in-use images (referenced by workload_images) by SBOM state and
// scan state relative to dbVersion. A zero dbVersion means no DB is loaded: no image is current
// or failed.
func (db *DB) CountImageStates(ctx context.Context, dbVersion time.Time) ([]ImageStateCount, error) {
	var version *time.Time
	if !dbVersion.IsZero() {
		version = &dbVersion
	}
	rows, err := db.pool.Query(ctx, `
		SELECT sbom_state,
			CASE
				WHEN sbom_state <> 'fetched' THEN ''
				WHEN scanned_db_version >= $1 THEN 'current'
				WHEN scan_failed_db_version >= $1 THEN 'failed'
				ELSE 'pending'
			END,
			count(*)
		FROM images i
		WHERE EXISTS (SELECT 1 FROM workload_images w WHERE w.image_id = i.id)
		GROUP BY 1, 2`,
		version,
	)
	if err != nil {
		return nil, fmt.Errorf("counting image states: %w", err)
	}
	counts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ImageStateCount, error) {
		var c ImageStateCount
		err := row.Scan(&c.SBOM, &c.Scan, &c.Count)
		return c, err
	})
	if err != nil {
		return nil, fmt.Errorf("counting image states: %w", err)
	}
	return counts, nil
}
