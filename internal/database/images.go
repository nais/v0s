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

// imageColumns are the images columns scanned by imageScan, qualified with the alias i.
const imageColumns = `i.id, i.name, i.digest, i.sbom_state, i.error, i.scanned_at, i.scanned_db_version`

// DueSBOMFetches returns up to limit images that are in use (referenced by workloads), not
// fetched, and due (sbom_next_attempt_at <= now()), oldest due first. Only one caller at a time
// may fetch: an image is returned again until its fetch is recorded.
func (db *DB) DueSBOMFetches(ctx context.Context, limit int) ([]v0s.Image, error) {
	rows, err := db.pool.Query(ctx, `
		SELECT `+imageColumns+`
		FROM images i
		WHERE i.sbom_state <> 'fetched'
			AND i.sbom_next_attempt_at <= now()
			AND EXISTS (SELECT 1 FROM workloads w WHERE w.image_id = i.id)
		ORDER BY i.sbom_next_attempt_at, i.id
		LIMIT $1`,
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("listing due sbom fetches: %w", err)
	}
	images, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (v0s.Image, error) {
		var img imageScan
		err := row.Scan(img.dest()...)
		return img.image(), err
	})
	if err != nil {
		return nil, fmt.Errorf("listing due sbom fetches: %w", err)
	}
	return images, nil
}

// StoreSBOM stores the verified SBOM (gzip-compressed) and marks the image fetched. It is
// write-once: if the image's SBOM is already fetched, the stored document is kept, since findings
// and components were derived from it. A deleted image is left alone.
func (db *DB) StoreSBOM(ctx context.Context, imageID int64, document []byte) error {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(document); err != nil {
		return fmt.Errorf("compressing sbom: %w", err)
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("compressing sbom: %w", err)
	}

	if _, err := db.pool.Exec(ctx, `
		UPDATE images SET sbom = $2, sbom_state = 'fetched', error = ''
		WHERE id = $1 AND sbom IS NULL`,
		imageID, buf.Bytes(),
	); err != nil {
		return fmt.Errorf("storing sbom: %w", err)
	}
	return nil
}

// RecordSBOMFailure marks the image missing or failed with a message and the next attempt time.
// An image whose SBOM has been fetched in the meantime is left alone.
func (db *DB) RecordSBOMFailure(ctx context.Context, imageID int64, state v0s.SBOMState, msg string, retryAt time.Time) error {
	if state != v0s.SBOMMissing && state != v0s.SBOMFailed {
		return fmt.Errorf("recording sbom failure: invalid state %q", state)
	}
	if _, err := db.pool.Exec(ctx, `
		UPDATE images
		SET sbom_state = $2, error = $3, sbom_next_attempt_at = $4
		WHERE id = $1 AND sbom_state <> 'fetched'`,
		imageID, string(state), msg, retryAt,
	); err != nil {
		return fmt.Errorf("recording sbom failure: %w", err)
	}
	return nil
}

// DeleteUnusedImages deletes the images no workload uses, with their components and findings.
// It must not run concurrently with SyncWorkloadImages, which could reference an image being deleted.
func (db *DB) DeleteUnusedImages(ctx context.Context) (int64, error) {
	tag, err := db.pool.Exec(ctx, `
		DELETE FROM images i WHERE NOT EXISTS (SELECT 1 FROM workloads w WHERE w.image_id = i.id)`)
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
	// newer failed, and "pending" if NextScan would still hand it out.
	Scan  string
	Count int
}

// CountImageStates counts the in-use images (referenced by workloads) by SBOM state and
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
		WHERE EXISTS (SELECT 1 FROM workloads w WHERE w.image_id = i.id)
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
