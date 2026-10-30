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
	"github.com/nais/v0s"
)

// maxSBOMSize is the largest decompressed SBOM ClaimScan returns.
const maxSBOMSize = 256 << 20

// ScanJob is a claimed image and its SBOM.
type ScanJob struct {
	Image v0s.Image
	SBOM  []byte // decompressed
}

// ClaimScan claims one in-use, fetched image whose scan lease has expired and that has neither
// been scanned nor failed to scan with dbVersion or newer. It leases the image for lease and
// returns it with its SBOM. ok is false if no image needs scanning.
func (db *DB) ClaimScan(ctx context.Context, dbVersion time.Time, lease time.Duration) (job ScanJob, ok bool, err error) {
	var (
		img        imageScan
		compressed []byte
	)
	err = db.pool.QueryRow(ctx, `
		UPDATE images i SET scan_lease_until = now() + make_interval(secs => $2)
		FROM sboms s
		WHERE s.image_id = i.id AND i.id IN (
			SELECT id FROM images
			WHERE sbom_state = 'fetched'
				AND (scanned_db_version IS NULL OR scanned_db_version < $1)
				AND (scan_failed_db_version IS NULL OR scan_failed_db_version < $1)
				AND (scan_lease_until IS NULL OR scan_lease_until <= now())
				AND EXISTS (SELECT 1 FROM workload_images w WHERE w.image_id = images.id)
			ORDER BY scanned_db_version NULLS FIRST, id
			LIMIT 1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING `+imageColumns+`, s.document`,
		dbVersion, lease.Seconds(),
	).Scan(append(img.dest(), &compressed)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return ScanJob{}, false, nil
	}
	if err != nil {
		return ScanJob{}, false, fmt.Errorf("claiming scan: %w", err)
	}
	sbom, err := gunzip(compressed)
	if err != nil {
		return ScanJob{}, false, fmt.Errorf("decompressing sbom of image %d: %w", img.img.ID, err)
	}
	return ScanJob{Image: img.image(), SBOM: sbom}, true, nil
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

// RecordScanFailure records that scanning with dbVersion failed, and clears the lease. The image
// keeps its findings and scanned_db_version, and is not claimed again until a newer DB is loaded.
// An image already scanned with dbVersion or newer, or failed with a newer DB, is left alone.
func (db *DB) RecordScanFailure(ctx context.Context, imageID int64, dbVersion time.Time, msg string) error {
	if _, err := db.pool.Exec(ctx, `
		UPDATE images SET scan_error = $3, scan_failed_db_version = $2, scan_lease_until = NULL
		WHERE id = $1
			AND (scanned_db_version IS NULL OR scanned_db_version < $2)
			AND (scan_failed_db_version IS NULL OR scan_failed_db_version <= $2)`,
		imageID, dbVersion, msg,
	); err != nil {
		return fmt.Errorf("recording scan failure: %w", err)
	}
	return nil
}

type findingKey struct{ vulnerabilityID, purl string }

// StoreScan records a scan result. If the image already has scanned_db_version >= dbVersion it is
// a no-op. Otherwise, in one transaction, it upserts vulnerabilities and their aliases, writes
// finding events (appeared for new (vulnerability, purl) pairs, resolved for vanished ones),
// replaces findings while preserving first_seen_at for findings that persist, inserts components
// if the image has none (SBOMs are immutable), and marks the image scanned, clearing any recorded
// scan failure. Vulnerability rows from a newer DB than dbVersion are kept.
//
// Duplicate findings (same vulnerability and purl) and components (same purl) keep the first.
func (db *DB) StoreScan(ctx context.Context, imageID int64, dbVersion time.Time, r v0s.ScanResult) error {
	return pgx.BeginFunc(ctx, db.pool, func(tx pgx.Tx) error {
		var (
			name, digest string
			scanned      *time.Time
			now          time.Time
		)
		if err := tx.QueryRow(ctx, `
			SELECT name, digest, scanned_db_version, now() FROM images WHERE id = $1 FOR UPDATE`,
			imageID,
		).Scan(&name, &digest, &scanned, &now); err != nil {
			return fmt.Errorf("locking image %d: %w", imageID, err)
		}
		if scanned != nil && !scanned.Before(dbVersion) {
			return nil
		}

		if err := upsertVulnerabilities(ctx, tx, dbVersion, r.Vulnerabilities); err != nil {
			return err
		}
		if err := replaceFindings(ctx, tx, imageID, name, digest, dbVersion, now, r.Findings); err != nil {
			return err
		}
		if err := insertComponents(ctx, tx, imageID, r.Components); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx, `
			UPDATE images
			SET scanned_db_version = $2, scanned_at = now(), scan_error = '', scan_failed_db_version = NULL,
				scan_lease_until = NULL
			WHERE id = $1`,
			imageID, dbVersion,
		); err != nil {
			return fmt.Errorf("marking image scanned: %w", err)
		}
		return nil
	})
}

// upsertVulnerabilities inserts or updates vulnerabilities from dbVersion and adds missing
// aliases. A row from a newer DB is not overwritten. Rows are written in ID order so that
// concurrent scans lock shared rows in the same order.
func upsertVulnerabilities(ctx context.Context, tx pgx.Tx, dbVersion time.Time, vulns []v0s.Vulnerability) error {
	n := len(vulns)
	var (
		ids, titles, descriptions      = make([]string, n), make([]string, n), make([]string, n)
		severities, cvss, references   = make([]string, n), make([]string, n), make([]string, n)
		publishedAt, modifiedAt        = make([]pgtype.Timestamptz, n), make([]pgtype.Timestamptz, n)
		aliases, aliasVulnerabilityIDs []string
	)
	for i, v := range vulns {
		ids[i], titles[i], descriptions[i] = v.ID, v.Title, v.Description
		var err error
		if severities[i], err = jsonObject(v.Severities); err != nil {
			return fmt.Errorf("encoding severities of %s: %w", v.ID, err)
		}
		if cvss[i], err = jsonObject(v.CVSS); err != nil {
			return fmt.Errorf("encoding cvss of %s: %w", v.ID, err)
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
		INSERT INTO vulnerabilities AS v (id, title, description, severities, cvss, "references", published_at, modified_at, db_version)
		SELECT DISTINCT ON (t.id)
			t.id, t.title, t.description, t.severities, t.cvss,
			ARRAY(SELECT jsonb_array_elements_text(t.refs)), t.published_at, t.modified_at, $9::timestamptz
		FROM unnest($1::text[], $2::text[], $3::text[], $4::jsonb[], $5::jsonb[], $6::jsonb[], $7::timestamptz[], $8::timestamptz[])
			AS t (id, title, description, severities, cvss, refs, published_at, modified_at)
		ORDER BY t.id
		ON CONFLICT (id) DO UPDATE SET
			title = excluded.title,
			description = excluded.description,
			severities = excluded.severities,
			cvss = excluded.cvss,
			"references" = excluded."references",
			published_at = excluded.published_at,
			modified_at = excluded.modified_at,
			db_version = excluded.db_version,
			updated_at = now()
		WHERE v.db_version IS NULL OR v.db_version < excluded.db_version
			OR (v.db_version = excluded.db_version
				AND (v.title, v.description, v.severities, v.cvss, v."references", v.published_at, v.modified_at)
				IS DISTINCT FROM (excluded.title, excluded.description, excluded.severities, excluded.cvss,
					excluded."references", excluded.published_at, excluded.modified_at))`,
		ids, titles, descriptions, severities, cvss, references, publishedAt, modifiedAt, dbVersion,
	); err != nil {
		return fmt.Errorf("upserting vulnerabilities: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO vulnerability_aliases (alias, vulnerability_id)
		SELECT DISTINCT alias, vulnerability_id FROM unnest($1::text[], $2::text[]) AS t (alias, vulnerability_id)
		ORDER BY alias, vulnerability_id
		ON CONFLICT DO NOTHING`,
		aliases, aliasVulnerabilityIDs,
	); err != nil {
		return fmt.Errorf("inserting vulnerability aliases: %w", err)
	}
	return nil
}

// replaceFindings replaces the image's findings with fs and records the difference as finding
// events. Findings that persist keep their first_seen_at; new ones get now.
func replaceFindings(ctx context.Context, tx pgx.Tx, imageID int64, name, digest string, dbVersion, now time.Time, fs []v0s.Finding) error {
	rows, err := tx.Query(ctx, `SELECT vulnerability_id, purl, first_seen_at FROM findings WHERE image_id = $1`, imageID)
	if err != nil {
		return fmt.Errorf("reading findings: %w", err)
	}
	firstSeen := map[findingKey]time.Time{}
	var (
		k findingKey
		t time.Time
	)
	if _, err := pgx.ForEachRow(rows, []any{&k.vulnerabilityID, &k.purl, &t}, func() error {
		firstSeen[k] = t
		return nil
	}); err != nil {
		return fmt.Errorf("reading findings: %w", err)
	}

	var (
		current                         = map[findingKey]bool{}
		findingRows                     [][]any
		kinds, eventVulnIDs, eventPURLs []string
	)
	for _, f := range fs {
		k := findingKey{f.VulnerabilityID, f.PURL}
		if current[k] {
			continue
		}
		current[k] = true
		seen, ok := firstSeen[k]
		if !ok {
			seen = now
			kinds, eventVulnIDs, eventPURLs = append(kinds, "appeared"), append(eventVulnIDs, k.vulnerabilityID), append(eventPURLs, k.purl)
		}
		findingRows = append(findingRows, []any{
			imageID, f.VulnerabilityID, f.PURL, f.PackageKey, f.InstalledVersion, f.FixedVersion,
			f.Status, string(f.Severity), f.SeveritySource, f.DataSource, seen,
		})
	}
	for k := range firstSeen {
		if !current[k] {
			kinds, eventVulnIDs, eventPURLs = append(kinds, "resolved"), append(eventVulnIDs, k.vulnerabilityID), append(eventPURLs, k.purl)
		}
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO finding_events (image_name, image_digest, vulnerability_id, purl, kind, db_version)
		SELECT $1, $2, t.vulnerability_id, t.purl, t.kind, $3
		FROM unnest($4::text[], $5::text[], $6::text[]) AS t (kind, vulnerability_id, purl)`,
		name, digest, dbVersion, kinds, eventVulnIDs, eventPURLs,
	); err != nil {
		return fmt.Errorf("inserting finding events: %w", err)
	}

	if _, err := tx.Exec(ctx, `DELETE FROM findings WHERE image_id = $1`, imageID); err != nil {
		return fmt.Errorf("deleting findings: %w", err)
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"findings"}, []string{
		"image_id", "vulnerability_id", "purl", "package_key", "installed_version", "fixed_version",
		"status", "severity", "severity_source", "data_source", "first_seen_at",
	}, pgx.CopyFromRows(findingRows)); err != nil {
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
