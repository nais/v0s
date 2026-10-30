package database

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s"
)

// imageColumns are the images columns scanned by scanImage, qualified with the alias i.
const imageColumns = `i.id, i.name, i.digest, i.sbom_state, i.sbom_error, i.scanned_at, i.scanned_db_version, i.scan_error`

// scanImage scans imageColumns, followed by extra destinations.
func scanImage(row pgx.Row, extra ...any) (v0s.Image, error) {
	var (
		img                         v0s.Image
		state                       string
		scannedAt, scannedDBVersion *time.Time
	)
	dest := append([]any{&img.ID, &img.Name, &img.Digest, &state, &img.SBOMError, &scannedAt, &scannedDBVersion, &img.ScanError}, extra...)
	if err := row.Scan(dest...); err != nil {
		return v0s.Image{}, err
	}
	img.SBOMState = v0s.SBOMState(state)
	if scannedAt != nil {
		img.ScannedAt = *scannedAt
	}
	if scannedDBVersion != nil {
		img.ScannedDBVersion = *scannedDBVersion
	}
	return img, nil
}

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
	images, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (v0s.Image, error) { return scanImage(row) })
	if err != nil {
		return nil, fmt.Errorf("claiming sbom fetches: %w", err)
	}
	return images, nil
}

// StoreSBOM stores the verified SBOM (gzip-compressed) and marks the image fetched.
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
		tag, err := tx.Exec(ctx, `
			UPDATE images SET sbom_state = 'fetched', sbom_error = '', sbom_fetched_at = now()
			WHERE id = $1`,
			imageID,
		)
		if err != nil {
			return fmt.Errorf("marking sbom fetched: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("storing sbom: image %d not found", imageID)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO sboms (image_id, document) VALUES ($1, $2)
			ON CONFLICT (image_id) DO UPDATE SET document = excluded.document`,
			imageID, buf.Bytes(),
		); err != nil {
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
