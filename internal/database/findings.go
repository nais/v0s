package database

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/purl"
	"github.com/package-url/packageurl-go"
)

// Errors the read path and suppressions return for requests they reject.
// The message of an error wrapping one of these is safe to show to clients.
var (
	ErrInvalid        = errors.New("invalid argument")
	ErrNotFound       = errors.New("not found")
	ErrAlreadyRevoked = errors.New("already revoked")
	// ErrConflict means a concurrent request changed the same rows. Retrying may succeed.
	ErrConflict = errors.New("conflicting concurrent change")
)

const (
	defaultPageSize = 100
	maxPageSize     = 1000
)

// Page selects one page of a listing. Token is the next-page token returned
// with the previous page, or empty for the first page. Size defaults to 100
// and is capped at 1000.
type Page struct {
	Size  int
	Token string
}

func (p Page) limit() int {
	if p.Size <= 0 {
		return defaultPageSize
	}
	return min(p.Size, maxPageSize)
}

// decodePageToken decodes token into cursor. An empty token leaves cursor unchanged.
func decodePageToken(token string, cursor any) error {
	if token == "" {
		return nil
	}
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return fmt.Errorf("malformed page token: %w", ErrInvalid)
	}
	if err := json.Unmarshal(b, cursor); err != nil {
		return fmt.Errorf("malformed page token: %w", ErrInvalid)
	}
	return nil
}

func encodePageToken(cursor any) (string, error) {
	b, err := json.Marshal(cursor)
	if err != nil {
		return "", fmt.Errorf("encoding page token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// sqlArgs collects positional arguments for a dynamically built query.
type sqlArgs []any

// add appends v and returns its placeholder.
func (a *sqlArgs) add(v any) string {
	*a = append(*a, v)
	return "$" + strconv.Itoa(len(*a))
}

// imageColumns are the images columns that imageScan reads, for alias i.
const imageColumns = "i.id, i.name, i.digest, i.sbom_state, i.sbom_error, i.scanned_at, i.scanned_db_version, i.scan_error"

type imageScan struct {
	img                         v0s.Image
	scannedAt, scannedDBVersion pgtype.Timestamptz
}

func (s *imageScan) dest() []any {
	return []any{&s.img.ID, &s.img.Name, &s.img.Digest, &s.img.SBOMState, &s.img.SBOMError, &s.scannedAt, &s.scannedDBVersion, &s.img.ScanError}
}

func (s *imageScan) image() v0s.Image {
	img := s.img
	img.ScannedAt = s.scannedAt.Time
	img.ScannedDBVersion = s.scannedDBVersion.Time
	return img
}

// suppressionJoin matches the active suppression s for finding f in image i.
const suppressionJoin = `s.image_name = i.name AND s.package_key = f.package_key AND s.vulnerability_id = f.vulnerability_id
	AND s.revoked_at IS NULL AND (s.expires_at IS NULL OR s.expires_at > now())`

// vulnerabilityMatch returns a condition matching column against idOrAlias as an ID or an alias.
func vulnerabilityMatch(column, idOrAlias string, args *sqlArgs) string {
	p := args.add(idOrAlias)
	return fmt.Sprintf("(%s = %s OR %s IN (SELECT vulnerability_id FROM vulnerability_aliases WHERE alias = %s))", column, p, column, p)
}

// packageMatch returns a condition matching pkg: the exact purl column when
// pkg is a purl with a version, otherwise the package key column.
func packageMatch(purlColumn, keyColumn, pkg string, args *sqlArgs) (string, error) {
	p, err := packageurl.FromString(pkg)
	if err != nil {
		return "", fmt.Errorf("package %q is not a purl: %w", pkg, ErrInvalid)
	}
	if p.Version != "" {
		return purlColumn + " = " + args.add(pkg), nil
	}
	key, err := purl.PackageKey(pkg)
	if err != nil {
		return "", fmt.Errorf("package %q is not a purl: %w", pkg, ErrInvalid)
	}
	return keyColumn + " = " + args.add(key), nil
}

// SuppressedFilter selects findings by whether an active suppression covers them.
type SuppressedFilter int

// Suppressed filters. The zero value excludes suppressed findings.
const (
	SuppressedExclude SuppressedFilter = iota
	SuppressedInclude
	SuppressedOnly
)

// FindingFilter narrows findings. Empty fields do not filter, and slices match any value.
// Only images in use, that is referenced by workload_images, are considered.
type FindingFilter struct {
	Namespaces      []string
	Cluster         string
	Workload        string
	ImageName       string
	ImageDigest     string
	VulnerabilityID string // ID or alias
	Package         string // package key, or purl with version for an exact match
	Severities      []v0s.Severity
	HasFix          bool // only findings with a fixed version
	KEV             bool // only findings for vulnerabilities in CISA KEV
	Suppressed      SuppressedFilter
}

// conditions returns WHERE conditions on findings f and images i, and
// conditions on workload_images wi that select the workloads to consider.
func (f FindingFilter) conditions(args *sqlArgs) (where, workload []string, err error) {
	if len(f.Namespaces) > 0 {
		workload = append(workload, "wi.namespace = ANY("+args.add(f.Namespaces)+")")
	}
	if f.Cluster != "" {
		workload = append(workload, "wi.cluster = "+args.add(f.Cluster))
	}
	if f.Workload != "" {
		workload = append(workload, "wi.workload = "+args.add(f.Workload))
	}
	if f.ImageName != "" {
		where = append(where, "i.name = "+args.add(f.ImageName))
	}
	if f.ImageDigest != "" {
		where = append(where, "i.digest = "+args.add(f.ImageDigest))
	}
	if f.VulnerabilityID != "" {
		where = append(where, vulnerabilityMatch("f.vulnerability_id", f.VulnerabilityID, args))
	}
	if f.Package != "" {
		cond, err := packageMatch("f.purl", "f.package_key", f.Package, args)
		if err != nil {
			return nil, nil, err
		}
		where = append(where, cond)
	}
	if len(f.Severities) > 0 {
		sev := make([]string, len(f.Severities))
		for i, s := range f.Severities {
			sev[i] = string(s)
		}
		where = append(where, "f.severity = ANY("+args.add(sev)+")")
	}
	if f.HasFix {
		where = append(where, "f.fixed_version <> ''")
	}
	if f.KEV {
		where = append(where, "EXISTS (SELECT 1 FROM kev WHERE kev.cve = f.vulnerability_id)")
	}
	switch f.Suppressed {
	case SuppressedExclude:
		where = append(where, "NOT EXISTS (SELECT 1 FROM suppressions s WHERE "+suppressionJoin+")")
	case SuppressedInclude:
	case SuppressedOnly:
		where = append(where, "EXISTS (SELECT 1 FROM suppressions s WHERE "+suppressionJoin+")")
	default:
		return nil, nil, fmt.Errorf("unknown suppressed filter %d: %w", f.Suppressed, ErrInvalid)
	}
	return where, workload, nil
}

// inUse returns a condition that image i runs in a workload matching the workload conditions.
func inUse(workload []string) string {
	return "EXISTS (SELECT 1 FROM workload_images wi WHERE wi.image_id = i.id AND " + and(workload) + ")"
}

// and joins conditions with AND. No conditions is true.
func and(conds []string) string {
	if len(conds) == 0 {
		return "true"
	}
	return strings.Join(conds, " AND ")
}

// ImageFinding is a current finding in an image, with facts about its vulnerability.
type ImageFinding struct {
	Image       v0s.Image
	Finding     v0s.Finding
	Title       string
	CVSSScore   float64 // highest CVSS v3 score across sources, 0 if none
	EPSS        *v0s.EPSS
	KEV         *v0s.KEV
	FirstSeenAt time.Time
	Suppression *Suppression // the active suppression covering the finding, if any
}

type findingCursor struct {
	ImageID         int64  `json:"i"`
	VulnerabilityID string `json:"v"`
	PURL            string `json:"p"`
}

// ListFindings lists findings on images in use that match filter, ordered by
// image, vulnerability and purl. It returns the next page token, empty on the last page.
func (db *DB) ListFindings(ctx context.Context, filter FindingFilter, page Page) ([]ImageFinding, string, error) {
	var cursor findingCursor
	if err := decodePageToken(page.Token, &cursor); err != nil {
		return nil, "", err
	}
	var args sqlArgs
	where, workload, err := filter.conditions(&args)
	if err != nil {
		return nil, "", err
	}
	where = append(where, inUse(workload))
	if page.Token != "" {
		where = append(where, fmt.Sprintf("(f.image_id, f.vulnerability_id, f.purl) > (%s, %s, %s)",
			args.add(cursor.ImageID), args.add(cursor.VulnerabilityID), args.add(cursor.PURL)))
	}
	limit := page.limit()

	query := `SELECT ` + imageColumns + `,
		f.vulnerability_id, f.purl, f.package_key, f.installed_version, f.fixed_version, f.status,
		f.severity, f.severity_source, f.data_source, f.first_seen_at,
		v.title, coalesce((SELECT max((c.value->>'v3_score')::float8) FROM jsonb_each(v.cvss) c), 0),
		e.score, e.percentile, e.date,
		k.date_added, k.due_date, k.known_ransomware_campaign,
		s.id
	FROM findings f
	JOIN images i ON i.id = f.image_id
	JOIN vulnerabilities v ON v.id = f.vulnerability_id
	LEFT JOIN epss e ON e.cve = f.vulnerability_id
	LEFT JOIN kev k ON k.cve = f.vulnerability_id
	LEFT JOIN suppressions s ON ` + suppressionJoin + `
	WHERE ` + and(where) + `
	ORDER BY f.image_id, f.vulnerability_id, f.purl
	LIMIT ` + args.add(limit+1)

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, "", fmt.Errorf("listing findings: %w", err)
	}
	defer rows.Close()

	var (
		findings       []ImageFinding
		suppressionIDs []int64
	)
	for rows.Next() {
		var (
			img           imageScan
			fi            ImageFinding
			epss          epssScan
			kev           kevScan
			suppressionID *int64
		)
		dest := append(img.dest(),
			&fi.Finding.VulnerabilityID, &fi.Finding.PURL, &fi.Finding.PackageKey, &fi.Finding.InstalledVersion,
			&fi.Finding.FixedVersion, &fi.Finding.Status, &fi.Finding.Severity, &fi.Finding.SeveritySource,
			&fi.Finding.DataSource, &fi.FirstSeenAt, &fi.Title, &fi.CVSSScore,
		)
		dest = append(dest, epss.dest()...)
		dest = append(dest, kev.dest()...)
		dest = append(dest, &suppressionID)
		if err := rows.Scan(dest...); err != nil {
			return nil, "", fmt.Errorf("scanning finding: %w", err)
		}
		fi.Image = img.image()
		fi.EPSS = epss.epss(fi.Finding.VulnerabilityID)
		fi.KEV = kev.kev(fi.Finding.VulnerabilityID)
		if suppressionID != nil {
			fi.Suppression = &Suppression{ID: *suppressionID}
			suppressionIDs = append(suppressionIDs, *suppressionID)
		}
		findings = append(findings, fi)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("listing findings: %w", err)
	}

	var next string
	if len(findings) > limit {
		findings = findings[:limit]
		last := findings[limit-1]
		next, err = encodePageToken(findingCursor{ImageID: last.Image.ID, VulnerabilityID: last.Finding.VulnerabilityID, PURL: last.Finding.PURL})
		if err != nil {
			return nil, "", err
		}
	}

	if len(suppressionIDs) > 0 {
		rows, err := db.pool.Query(ctx, "SELECT "+suppressionColumns+" FROM suppressions WHERE id = ANY($1)", suppressionIDs)
		if err != nil {
			return nil, "", fmt.Errorf("listing finding suppressions: %w", err)
		}
		suppressions, err := pgx.CollectRows(rows, collectSuppression)
		if err != nil {
			return nil, "", fmt.Errorf("listing finding suppressions: %w", err)
		}
		byID := make(map[int64]Suppression, len(suppressions))
		for _, s := range suppressions {
			byID[s.ID] = s
		}
		for i := range findings {
			if s := findings[i].Suppression; s != nil {
				full := byID[s.ID]
				findings[i].Suppression = &full
			}
		}
	}
	return findings, next, nil
}

// epssScan reads e.score, e.percentile, e.date from a LEFT JOIN.
type epssScan struct {
	score, percentile *float64
	date              pgtype.Date
}

func (s *epssScan) dest() []any { return []any{&s.score, &s.percentile, &s.date} }

func (s *epssScan) epss(cve string) *v0s.EPSS {
	if s.score == nil {
		return nil
	}
	return &v0s.EPSS{CVE: cve, Score: *s.score, Percentile: *s.percentile, Date: s.date.Time}
}

// kevScan reads k.date_added, k.due_date, k.known_ransomware_campaign from a LEFT JOIN.
type kevScan struct {
	dateAdded, dueDate pgtype.Date
	ransomware         *bool
}

func (s *kevScan) dest() []any { return []any{&s.dateAdded, &s.dueDate, &s.ransomware} }

func (s *kevScan) kev(cve string) *v0s.KEV {
	if s.ransomware == nil {
		return nil
	}
	return &v0s.KEV{CVE: cve, DateAdded: s.dateAdded.Time, DueDate: s.dueDate.Time, KnownRansomwareCampaign: *s.ransomware}
}

// GroupBy is the dimension CountFindings groups by.
type GroupBy int

// Dimensions to count findings by.
const (
	GroupBySeverity GroupBy = iota + 1
	GroupByNamespace
	GroupByWorkload // key "cluster/namespace/name"
	GroupByImage    // key "name@digest"
	GroupByVulnerability
)

// FindingCount is the number of findings with one value of the grouped dimension.
type FindingCount struct {
	Key   string
	Count int64
}

// CountFindings counts findings on images in use that match filter, grouped
// by one dimension and ordered by key.
//
// Under GroupByNamespace and GroupByWorkload, a finding counts once for every
// matching workload running its image, since one image can run in several
// workloads. A namespace count is the sum over its workloads. Under the other
// groupings each finding counts once.
func (db *DB) CountFindings(ctx context.Context, filter FindingFilter, groupBy GroupBy) ([]FindingCount, error) {
	var args sqlArgs
	where, workload, err := filter.conditions(&args)
	if err != nil {
		return nil, err
	}

	var key string
	switch groupBy {
	case GroupBySeverity:
		key = "f.severity"
	case GroupByNamespace:
		key = "wi.namespace"
	case GroupByWorkload:
		key = "wi.cluster || '/' || wi.namespace || '/' || wi.workload"
	case GroupByImage:
		key = "i.name || '@' || i.digest"
	case GroupByVulnerability:
		key = "f.vulnerability_id"
	default:
		return nil, fmt.Errorf("group by is required: %w", ErrInvalid)
	}

	var query string
	if groupBy == GroupByNamespace || groupBy == GroupByWorkload {
		// One row per finding and workload running its image.
		query = `SELECT key, count(*) FROM (
			SELECT DISTINCT ` + key + ` AS key, wi.cluster, wi.namespace, wi.workload, f.image_id, f.vulnerability_id, f.purl
			FROM findings f
			JOIN images i ON i.id = f.image_id
			JOIN workload_images wi ON wi.image_id = i.id AND ` + and(workload) + `
			WHERE ` + and(where) + `
		) x
		GROUP BY key ORDER BY key`
	} else {
		where = append(where, inUse(workload))
		query = `SELECT ` + key + `, count(*)
		FROM findings f JOIN images i ON i.id = f.image_id
		WHERE ` + and(where) + `
		GROUP BY 1 ORDER BY 1`
	}

	rows, err := db.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("counting findings: %w", err)
	}
	counts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (FindingCount, error) {
		var c FindingCount
		err := row.Scan(&c.Key, &c.Count)
		return c, err
	})
	if err != nil {
		return nil, fmt.Errorf("counting findings: %w", err)
	}
	return counts, nil
}

// vulnerabilityIDs returns the vulnerability ID idOrAlias names: itself if it
// is an ID, otherwise every ID it is an alias of.
func vulnerabilityIDs(ctx context.Context, q pgxQuerier, idOrAlias string) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT id FROM vulnerabilities WHERE id = $1
		UNION ALL
		SELECT vulnerability_id FROM vulnerability_aliases
		WHERE alias = $1 AND NOT EXISTS (SELECT 1 FROM vulnerabilities WHERE id = $1)
		ORDER BY 1`, idOrAlias)
	if err != nil {
		return nil, fmt.Errorf("resolving vulnerability: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("resolving vulnerability: %w", err)
	}
	return ids, nil
}

// pgxQuerier is satisfied by both the pool and a transaction.
type pgxQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// VulnerabilityDetail is a vulnerability record with its EPSS score and KEV entry.
type VulnerabilityDetail struct {
	v0s.Vulnerability
	EPSS *v0s.EPSS
	KEV  *v0s.KEV
}

// GetVulnerability returns the vulnerability named by an ID or an alias.
// An alias of several vulnerabilities is ErrInvalid.
func (db *DB) GetVulnerability(ctx context.Context, idOrAlias string) (VulnerabilityDetail, error) {
	ids, err := vulnerabilityIDs(ctx, db.pool, idOrAlias)
	if err != nil {
		return VulnerabilityDetail{}, err
	}
	switch len(ids) {
	case 0:
		return VulnerabilityDetail{}, fmt.Errorf("vulnerability %q: %w", idOrAlias, ErrNotFound)
	case 1:
	default:
		return VulnerabilityDetail{}, fmt.Errorf("%q is an alias of several vulnerabilities (%s): %w", idOrAlias, strings.Join(ids, ", "), ErrInvalid)
	}

	var (
		d                       VulnerabilityDetail
		publishedAt, modifiedAt pgtype.Timestamptz
		epss                    epssScan
		kev                     kevScan
	)
	dest := []any{&d.ID, &d.Title, &d.Description, &d.Severities, &d.CVSS, &d.References, &publishedAt, &modifiedAt, &d.Aliases}
	dest = append(dest, epss.dest()...)
	dest = append(dest, kev.dest()...)
	err = db.pool.QueryRow(ctx, `
		SELECT v.id, v.title, v.description, v.severities, v.cvss, v."references", v.published_at, v.modified_at,
			ARRAY(SELECT alias FROM vulnerability_aliases WHERE vulnerability_id = v.id ORDER BY alias),
			e.score, e.percentile, e.date,
			k.date_added, k.due_date, k.known_ransomware_campaign
		FROM vulnerabilities v
		LEFT JOIN epss e ON e.cve = v.id
		LEFT JOIN kev k ON k.cve = v.id
		WHERE v.id = $1`, ids[0]).Scan(dest...)
	if err != nil {
		return VulnerabilityDetail{}, fmt.Errorf("getting vulnerability: %w", err)
	}
	d.PublishedAt = publishedAt.Time
	d.ModifiedAt = modifiedAt.Time
	d.EPSS = epss.epss(d.ID)
	d.KEV = kev.kev(d.ID)
	return d, nil
}

// FindingEvent is a recorded change in an image's findings.
type FindingEvent struct {
	ID              int64
	ImageName       string
	ImageDigest     string
	VulnerabilityID string
	PURL            string
	Kind            string // "appeared" or "resolved"
	DBVersion       time.Time
	CreatedAt       time.Time
}

// FindingEventFilter narrows finding events. Empty fields do not filter.
type FindingEventFilter struct {
	ImageName       string
	ImageDigest     string
	VulnerabilityID string   // ID or alias
	Namespaces      []string // events whose image currently runs in one of these namespaces
	Since           time.Time
}

// ListFindingEvents lists finding events matching filter, oldest first.
func (db *DB) ListFindingEvents(ctx context.Context, filter FindingEventFilter, page Page) ([]FindingEvent, string, error) {
	var cursor struct {
		ID int64 `json:"id"`
	}
	if err := decodePageToken(page.Token, &cursor); err != nil {
		return nil, "", err
	}
	var (
		args  sqlArgs
		where = []string{"ev.id > " + args.add(cursor.ID)}
	)
	if filter.ImageName != "" {
		where = append(where, "ev.image_name = "+args.add(filter.ImageName))
	}
	if filter.ImageDigest != "" {
		where = append(where, "ev.image_digest = "+args.add(filter.ImageDigest))
	}
	if filter.VulnerabilityID != "" {
		where = append(where, vulnerabilityMatch("ev.vulnerability_id", filter.VulnerabilityID, &args))
	}
	if len(filter.Namespaces) > 0 {
		where = append(where, `EXISTS (SELECT 1 FROM images i JOIN workload_images wi ON wi.image_id = i.id
			WHERE i.name = ev.image_name AND i.digest = ev.image_digest AND wi.namespace = ANY(`+args.add(filter.Namespaces)+`))`)
	}
	if !filter.Since.IsZero() {
		where = append(where, "ev.created_at >= "+args.add(filter.Since))
	}
	limit := page.limit()

	rows, err := db.pool.Query(ctx, `
		SELECT ev.id, ev.image_name, ev.image_digest, ev.vulnerability_id, ev.purl, ev.kind, ev.db_version, ev.created_at
		FROM finding_events ev
		WHERE `+and(where)+`
		ORDER BY ev.id
		LIMIT `+args.add(limit+1), args...)
	if err != nil {
		return nil, "", fmt.Errorf("listing finding events: %w", err)
	}
	events, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (FindingEvent, error) {
		var e FindingEvent
		err := row.Scan(&e.ID, &e.ImageName, &e.ImageDigest, &e.VulnerabilityID, &e.PURL, &e.Kind, &e.DBVersion, &e.CreatedAt)
		return e, err
	})
	if err != nil {
		return nil, "", fmt.Errorf("listing finding events: %w", err)
	}

	var next string
	if len(events) > limit {
		events = events[:limit]
		cursor.ID = events[limit-1].ID
		if next, err = encodePageToken(cursor); err != nil {
			return nil, "", err
		}
	}
	return events, next, nil
}
