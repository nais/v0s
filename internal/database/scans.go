package database

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v0s/internal/v0s"
)

// maxSBOMSize is the largest decompressed SBOM NextScan returns.
const maxSBOMSize = 256 << 20

// maxScanAttempts is how often NextScan hands out an image for one DB version without a result
// being recorded. A scan that kills the process records nothing, so without a cap the image would
// crash v0s again after every restart.
const maxScanAttempts = 3

// ScanJob is an image to scan and its SBOM.
type ScanJob struct {
	Image v0s.Image
	SBOM  []byte // decompressed
}

// NextScan returns one in-use, fetched image that has neither been scanned nor failed to scan with
// dbVersion or newer, with its SBOM. ok is false if no image needs scanning. Only one caller at a
// time may scan: NextScan returns the same image until a result is recorded.
//
// Each call counts as an attempt for dbVersion; another DB version starts the count again. An image
// already handed out maxScanAttempts times for dbVersion is not handed out again but recorded as
// failed with dbVersion.
func (db *DB) NextScan(ctx context.Context, dbVersion time.Time) (job ScanJob, ok bool, err error) {
	for {
		var (
			img        imageScan
			compressed []byte
			attempts   int
		)
		err = db.pool.QueryRow(ctx, `
			UPDATE images i SET
				scan_attempts = CASE WHEN i.scan_attempts_db_version = $1 THEN i.scan_attempts + 1 ELSE 1 END,
				scan_attempts_db_version = $1
			WHERE i.id = (
				SELECT id FROM images
				WHERE sbom_state = 'fetched'
					AND (scanned_db_version IS NULL OR scanned_db_version < $1)
					AND (scan_failed_db_version IS NULL OR scan_failed_db_version < $1)
					AND EXISTS (SELECT 1 FROM workloads w WHERE w.image_id = images.id)
				ORDER BY scanned_db_version NULLS FIRST, id
				LIMIT 1
			)
			RETURNING `+imageColumns+`, i.sbom, i.scan_attempts`,
			dbVersion,
		).Scan(append(img.dest(), &compressed, &attempts)...)
		if errors.Is(err, pgx.ErrNoRows) {
			return ScanJob{}, false, nil
		}
		if err != nil {
			return ScanJob{}, false, fmt.Errorf("claiming scan: %w", err)
		}
		if attempts > maxScanAttempts {
			msg := fmt.Sprintf("abandoned after %d attempts", maxScanAttempts)
			if err := db.RecordScanFailure(ctx, img.id.Int64, dbVersion, msg); err != nil {
				return ScanJob{}, false, err
			}
			continue
		}
		sbom, err := gunzip(compressed)
		if err != nil {
			// Retrying cannot help, so record it as a failed scan with this DB.
			err = fmt.Errorf("decompressing sbom of image %d: %w", img.id.Int64, err)
			if rerr := db.RecordScanFailure(ctx, img.id.Int64, dbVersion, err.Error()); rerr != nil {
				return ScanJob{}, false, errors.Join(err, rerr)
			}
			return ScanJob{}, false, err
		}
		return ScanJob{Image: img.image(), SBOM: sbom}, true, nil
	}
}

func gunzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out, err := io.ReadAll(io.LimitReader(zr, maxSBOMSize+1))
	if err != nil {
		return nil, err
	}
	if len(out) > maxSBOMSize {
		return nil, fmt.Errorf("larger than %d bytes", maxSBOMSize)
	}
	return out, nil
}

// RecordScanFailure records that scanning with dbVersion failed, and clears the attempt count.
// The image keeps its findings and scanned_db_version, and is not handed out again until a newer
// DB is loaded. An image already scanned with dbVersion or newer, or failed with a newer DB, or
// deleted, is left alone.
func (db *DB) RecordScanFailure(ctx context.Context, imageID int64, dbVersion time.Time, msg string) error {
	if _, err := db.pool.Exec(ctx, `
		UPDATE images SET error = $3, scan_failed_db_version = $2, scan_attempts = 0
		WHERE id = $1
			AND (scanned_db_version IS NULL OR scanned_db_version < $2)
			AND (scan_failed_db_version IS NULL OR scan_failed_db_version <= $2)`,
		imageID, dbVersion, msg,
	); err != nil {
		return fmt.Errorf("recording scan failure: %w", err)
	}
	return nil
}

// StoreScan records a scan result. If the image already has scanned_db_version >= dbVersion, or
// has been deleted, it is a no-op. Otherwise, in one transaction, it upserts vulnerabilities and
// their aliases, replaces findings, inserts components if the image has none (SBOMs are
// immutable), and marks the image scanned, clearing any recorded scan failure and the attempt
// count. Vulnerability rows from a newer DB than dbVersion are kept.
//
// Duplicate findings (same vulnerability and purl) and components (same purl) keep the first.
func (db *DB) StoreScan(ctx context.Context, imageID int64, dbVersion time.Time, r v0s.ScanResult) error {
	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		var scanned *time.Time
		err := tx.QueryRow(ctx, `SELECT scanned_db_version FROM images WHERE id = $1 FOR UPDATE`, imageID).Scan(&scanned)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // no workload uses it anymore
		}
		if err != nil {
			return fmt.Errorf("locking image %d: %w", imageID, err)
		}
		if scanned != nil && !scanned.Before(dbVersion) {
			return nil
		}

		if err := upsertVulnerabilities(ctx, tx, dbVersion, r.Vulnerabilities); err != nil {
			return err
		}
		if err := replaceFindings(ctx, tx, imageID, r.Findings); err != nil {
			return err
		}
		if err := insertComponents(ctx, tx, imageID, r.Components); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `
			UPDATE images
			SET scanned_db_version = $2, scanned_at = now(), error = '', scan_failed_db_version = NULL, scan_attempts = 0
			WHERE id = $1`,
			imageID, dbVersion,
		); err != nil {
			return fmt.Errorf("marking image scanned: %w", err)
		}
		return nil
	})
}

// upsertVulnerabilities inserts or updates vulnerabilities from dbVersion and adds missing
// aliases. A row from the same or a newer DB is not overwritten.
func upsertVulnerabilities(ctx context.Context, tx pgx.Tx, dbVersion time.Time, vulns []v0s.Vulnerability) error {
	n := len(vulns)
	var (
		ids, titles, descriptions      = make([]string, n), make([]string, n), make([]string, n)
		severities, references         = make([]string, n), make([]string, n)
		publishedAt, modifiedAt        = make([]pgtype.Timestamptz, n), make([]pgtype.Timestamptz, n)
		aliases, aliasVulnerabilityIDs []string
	)
	for i, v := range vulns {
		ids[i], titles[i], descriptions[i] = v.ID, v.Title, v.Description
		var err error
		if severities[i], err = jsonObject(v.Severities); err != nil {
			return fmt.Errorf("encoding severities of %s: %w", v.ID, err)
		}
		if references[i], err = jsonArray(v.References); err != nil {
			return fmt.Errorf("encoding references of %s: %w", v.ID, err)
		}
		publishedAt[i] = pgtype.Timestamptz{Time: v.PublishedAt, Valid: !v.PublishedAt.IsZero()}
		modifiedAt[i] = pgtype.Timestamptz{Time: v.ModifiedAt, Valid: !v.ModifiedAt.IsZero()}
		for _, a := range v.Aliases {
			aliases = append(aliases, a)
			aliasVulnerabilityIDs = append(aliasVulnerabilityIDs, v.ID)
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO vulnerabilities AS v (id, title, description, severities, "references", published_at, modified_at, db_version)
		SELECT DISTINCT ON (t.id)
			t.id, t.title, t.description, t.severities,
			ARRAY(SELECT jsonb_array_elements_text(t.refs)), t.published_at, t.modified_at, $8::timestamptz
		FROM unnest($1::text[], $2::text[], $3::text[], $4::jsonb[], $5::jsonb[], $6::timestamptz[], $7::timestamptz[])
			AS t (id, title, description, severities, refs, published_at, modified_at)
		ORDER BY t.id
		ON CONFLICT (id) DO UPDATE SET
			title = excluded.title,
			description = excluded.description,
			severities = excluded.severities,
			"references" = excluded."references",
			published_at = excluded.published_at,
			modified_at = excluded.modified_at,
			db_version = excluded.db_version
		WHERE v.db_version < excluded.db_version`,
		ids, titles, descriptions, severities, references, publishedAt, modifiedAt, dbVersion,
	); err != nil {
		return fmt.Errorf("upserting vulnerabilities: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO vulnerability_aliases (alias, vulnerability_id)
		SELECT DISTINCT alias, vulnerability_id FROM unnest($1::text[], $2::text[]) AS t (alias, vulnerability_id)
		ON CONFLICT DO NOTHING`,
		aliases, aliasVulnerabilityIDs,
	); err != nil {
		return fmt.Errorf("inserting vulnerability aliases: %w", err)
	}
	return nil
}

// replaceFindings replaces the image's findings with fs.
func replaceFindings(ctx context.Context, tx pgx.Tx, imageID int64, fs []v0s.Finding) error {
	type key struct{ vulnerabilityID, purl string }
	var (
		seen = map[key]bool{}
		rows [][]any
	)
	for _, f := range fs {
		k := key{f.VulnerabilityID, f.PURL}
		if seen[k] {
			continue
		}
		seen[k] = true
		rows = append(rows, []any{
			imageID, f.VulnerabilityID, f.PURL, f.PackageKey, f.InstalledVersion, f.FixedVersion,
			f.Status, string(f.Severity), f.SeveritySource, f.DataSource,
		})
	}

	if _, err := tx.Exec(ctx, `DELETE FROM findings WHERE image_id = $1`, imageID); err != nil {
		return fmt.Errorf("deleting findings: %w", err)
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"findings"}, []string{
		"image_id", "vulnerability_id", "purl", "package_key", "installed_version", "fixed_version",
		"status", "severity", "severity_source", "data_source",
	}, pgx.CopyFromRows(rows)); err != nil {
		return fmt.Errorf("inserting findings: %w", err)
	}
	return nil
}

// insertComponents inserts the image's components unless it already has them. SBOMs are
// immutable, so components never change once stored.
func insertComponents(ctx context.Context, tx pgx.Tx, imageID int64, cs []v0s.Component) error {
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM components WHERE image_id = $1)`, imageID).Scan(&exists); err != nil {
		return fmt.Errorf("checking components: %w", err)
	}
	if exists {
		return nil
	}

	seen := map[string]bool{}
	var rows [][]any
	for _, c := range cs {
		if seen[c.PURL] {
			continue
		}
		seen[c.PURL] = true
		rows = append(rows, []any{imageID, c.PURL, c.PackageKey, c.Name, c.Version})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"components"},
		[]string{"image_id", "purl", "package_key", "name", "version"}, pgx.CopyFromRows(rows),
	); err != nil {
		return fmt.Errorf("inserting components: %w", err)
	}
	return nil
}

// jsonObject encodes m as a JSON object, {} if m is nil.
func jsonObject[V any](m map[string]V) (string, error) {
	if m == nil {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	return string(b), err
}

// jsonArray encodes s as a JSON array, [] if s is nil.
func jsonArray(s []string) (string, error) {
	if s == nil {
		return "[]", nil
	}
	b, err := json.Marshal(s)
	return string(b), err
}
