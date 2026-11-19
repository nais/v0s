package database

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/nais/v0s/internal/purl"
	"github.com/nais/v0s/internal/v0s"
	"github.com/package-url/packageurl-go"
)

// Errors the read path and suppressions return for requests they reject.
// The message of an error wrapping one of these is safe to show to clients.
var (
	ErrInvalid     = errors.New("invalid argument")
	ErrNotFound    = errors.New("not found")
	ErrUnavailable = errors.New("CISA KEV catalog is not available")
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

// imageScan scans imageColumns. All are NULL when a LEFT JOIN found no image.
type imageScan struct {
	id                              pgtype.Int8
	name, digest, sbomState, errMsg pgtype.Text
	scannedAt, scannedDBVersion     pgtype.Timestamptz
}

func (s *imageScan) dest() []any {
	return []any{&s.id, &s.name, &s.digest, &s.sbomState, &s.errMsg, &s.scannedAt, &s.scannedDBVersion}
}

func (s *imageScan) found() bool { return s.id.Valid }

func (s *imageScan) image() v0s.Image {
	return v0s.Image{
		ID:               s.id.Int64,
		Name:             s.name.String,
		Digest:           s.digest.String,
		SBOMState:        v0s.SBOMState(s.sbomState.String),
		Error:            s.errMsg.String,
		ScannedAt:        s.scannedAt.Time,
		ScannedDBVersion: s.scannedDBVersion.Time,
	}
}

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
		return purlColumn + " = " + args.add(p.ToString()), nil
	}
	key, err := purl.PackageKey(pkg)
	if err != nil {
		return "", fmt.Errorf("package %q is not a purl: %w", pkg, ErrInvalid)
	}
	return keyColumn + " = " + args.add(key), nil
}

// SuppressedFilter selects findings by whether their workload has a matching assessment.
type SuppressedFilter int

// Suppressed filters. The zero value excludes suppressed findings.
const (
	SuppressedExclude SuppressedFilter = iota
	SuppressedInclude
	SuppressedOnly
)

// FindingFilter narrows findings. Empty fields do not filter, and slices match any value.
type FindingFilter struct {
	Teams              []string
	Environment        string
	Workload           string
	ImageName          string
	ImageDigest        string
	VulnerabilityID    string // ID or alias
	Package            string // package key, or purl with version for an exact match
	PackageType        string
	Severities         []v0s.Severity
	HasFix             bool // only findings with a fixed version
	OnlyKnownExploited bool // only findings for vulnerabilities in CISA KEV
	Suppressed         SuppressedFilter
}

// conditions returns WHERE conditions on findingsFrom.
func (f FindingFilter) conditions(args *sqlArgs) ([]string, error) {
	var where []string
	if len(f.Teams) > 0 {
		where = append(where, "w.team = ANY("+args.add(f.Teams)+")")
	}
	if f.Environment != "" {
		where = append(where, "w.environment = "+args.add(f.Environment))
	}
	if f.Workload != "" {
		where = append(where, "w.name = "+args.add(f.Workload))
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
			return nil, err
		}
		where = append(where, cond)
	}
	if f.PackageType != "" {
		if !packageurl.TypePattern.MatchString(f.PackageType) {
			return nil, fmt.Errorf("package type %q is invalid: %w", f.PackageType, ErrInvalid)
		}
		where = append(where, "starts_with(f.package_key, "+args.add("pkg:"+strings.ToLower(f.PackageType)+"/")+")")
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
	if f.OnlyKnownExploited {
		where = append(where, "EXISTS (SELECT 1 FROM kev WHERE kev.cve = f.vulnerability_id)")
	}
	switch f.Suppressed {
	case SuppressedExclude:
		where = append(where, "s.team IS NULL")
	case SuppressedInclude:
	case SuppressedOnly:
		where = append(where, "s.team IS NOT NULL")
	default:
		return nil, fmt.Errorf("unknown suppressed filter %d: %w", f.Suppressed, ErrInvalid)
	}
	return where, nil
}

// findingsFrom joins each finding f in image i to every workload w using the image, and to the
// workload's suppression s of it, if any. The suppression key is the primary key of
// suppressions, so each finding and workload is one row.
const findingsFrom = `findings f
	JOIN images i ON i.id = f.image_id
	JOIN workloads w ON w.image_id = f.image_id
	LEFT JOIN suppressions s ON s.team = w.team AND s.environment = w.environment
		AND s.workload = w.name AND s.image_name = i.name
		AND s.package_key = f.package_key AND s.vulnerability_id = f.vulnerability_id`

// and joins conditions with AND. No conditions is true.
func and(conds []string) string {
	if len(conds) == 0 {
		return "true"
	}
	return strings.Join(conds, " AND ")
}

// WorkloadFinding is a current finding in a workload's image, with facts about its vulnerability.
type WorkloadFinding struct {
	Workload       WorkloadRef
	Image          v0s.Image
	Finding        v0s.Finding
	EPSS           *v0s.EPSS
	KnownExploited bool // according to CISA KEV
	// Suppression is this workload's active suppression of the finding, nil if none.
	Suppression *Suppression
}

type findingCursor struct {
	Environment     string `json:"e"`
	Team            string `json:"t"`
	Workload        string `json:"w"`
	VulnerabilityID string `json:"v"`
	PURL            string `json:"p"`
}

// FindingList is one page of findings with package type counts for every page.
// NextPageToken is empty on the last page.
type FindingList struct {
	Findings          []WorkloadFinding
	PackageTypeCounts []FindingCount
	NextPageToken     string
}

// ListFindings lists the findings of workloads that match filter, ordered by
// workload, vulnerability and purl, with package type counts before pagination.
func (db *DB) ListFindings(ctx context.Context, filter FindingFilter, page Page) (FindingList, error) {
	var cursor findingCursor
	if err := decodePageToken(page.Token, &cursor); err != nil {
		return FindingList{}, err
	}
	var args sqlArgs
	where, err := filter.conditions(&args)
	if err != nil {
		return FindingList{}, err
	}
	countWhere, countArgs := slices.Clone(where), slices.Clone(args)
	if err := db.requireKEVCatalog(ctx); err != nil {
		return FindingList{}, err
	}
	if page.Token != "" {
		env, team, workload := args.add(cursor.Environment), args.add(cursor.Team), args.add(cursor.Workload)
		// Split the cursor at the workload boundary to give Postgres an index
		// bound and avoid underestimating a row comparison spanning two tables.
		// Include the cursor workload only for its remaining findings.
		where = append(where,
			fmt.Sprintf("(w.environment, w.team, w.name) >= (%s, %s, %s)", env, team, workload),
			fmt.Sprintf("((w.environment, w.team, w.name) <> (%s, %s, %s) OR (f.vulnerability_id, f.purl) > (%s, %s))",
				env, team, workload, args.add(cursor.VulnerabilityID), args.add(cursor.PURL)))
	}
	limit := page.limit()

	tx, err := db.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return FindingList{}, fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	rows, err := tx.Query(ctx, `
		SELECT w.environment, w.team, w.name, `+imageColumns+`,
			f.vulnerability_id, f.purl, f.package_key, f.installed_version, f.fixed_version, f.status,
			f.severity, f.severity_source, f.data_source,
			e.score, e.date, k.cve IS NOT NULL,
			s.state, s.detail, s.updated_by, s.updated_at
		FROM `+findingsFrom+`
		LEFT JOIN epss e ON e.cve = f.vulnerability_id
		LEFT JOIN kev k ON k.cve = f.vulnerability_id
		WHERE `+and(where)+`
		ORDER BY w.environment, w.team, w.name, f.vulnerability_id, f.purl
		LIMIT `+args.add(limit+1), args...)
	if err != nil {
		return FindingList{}, fmt.Errorf("listing findings: %w", err)
	}
	findings, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (WorkloadFinding, error) {
		var (
			fi                       WorkloadFinding
			img                      imageScan
			epss                     epssScan
			state, detail, updatedBy *string
			updatedAt                pgtype.Timestamptz
		)
		dest := []any{&fi.Workload.Environment, &fi.Workload.Team, &fi.Workload.Name}
		dest = append(dest, img.dest()...)
		dest = append(dest,
			&fi.Finding.VulnerabilityID, &fi.Finding.PURL, &fi.Finding.PackageKey, &fi.Finding.InstalledVersion,
			&fi.Finding.FixedVersion, &fi.Finding.Status, &fi.Finding.Severity, &fi.Finding.SeveritySource,
			&fi.Finding.DataSource,
		)
		dest = append(dest, epss.dest()...)
		dest = append(dest, &fi.KnownExploited, &state, &detail, &updatedBy, &updatedAt)
		if err := row.Scan(dest...); err != nil {
			return WorkloadFinding{}, err
		}
		fi.Image = img.image()
		fi.EPSS = epss.epss(fi.Finding.VulnerabilityID)
		if state != nil {
			fi.Suppression = &Suppression{
				SuppressionKey: SuppressionKey{
					Environment:     fi.Workload.Environment,
					Workload:        fi.Workload.Name,
					ImageName:       fi.Image.Name,
					Package:         fi.Finding.PackageKey,
					VulnerabilityID: fi.Finding.VulnerabilityID,
				},
				Team:      fi.Workload.Team,
				State:     *state,
				Detail:    *detail,
				UpdatedBy: *updatedBy,
				UpdatedAt: updatedAt.Time,
			}
		}
		return fi, nil
	})
	if err != nil {
		return FindingList{}, fmt.Errorf("listing findings: %w", err)
	}

	var next string
	if len(findings) > limit {
		findings = findings[:limit]
		last := findings[limit-1]
		next, err = encodePageToken(findingCursor{
			Environment:     last.Workload.Environment,
			Team:            last.Workload.Team,
			Workload:        last.Workload.Name,
			VulnerabilityID: last.Finding.VulnerabilityID,
			PURL:            last.Finding.PURL,
		})
		if err != nil {
			return FindingList{}, err
		}
	}
	counts, err := countFindings(ctx, tx, GroupByPackageType, countWhere, countArgs)
	if err != nil {
		return FindingList{}, err
	}
	return FindingList{Findings: findings, PackageTypeCounts: counts, NextPageToken: next}, nil
}

// epssScan reads e.score and e.date from a LEFT JOIN.
type epssScan struct {
	score *float64
	date  pgtype.Date
}

func (s *epssScan) dest() []any { return []any{&s.score, &s.date} }

func (s *epssScan) epss(cve string) *v0s.EPSS {
	if s.score == nil {
		return nil
	}
	return &v0s.EPSS{CVE: cve, Score: *s.score, Date: s.date.Time}
}

// GroupBy is the dimension CountFindings groups by.
type GroupBy int

// Dimensions to count findings by.
const (
	GroupBySeverity GroupBy = iota + 1
	GroupByTeam
	GroupByWorkload // key "environment/team/name"
	GroupByImage    // key "name@digest"
	GroupByVulnerability
	GroupByPackageType
)

func (g GroupBy) key() string {
	switch g {
	case GroupBySeverity:
		return "f.severity"
	case GroupByTeam:
		return "w.team"
	case GroupByWorkload:
		return "w.environment || '/' || w.team || '/' || w.name"
	case GroupByImage:
		return "i.name || '@' || i.digest"
	case GroupByVulnerability:
		return "f.vulnerability_id"
	case GroupByPackageType:
		return `split_part(split_part(f.package_key, '/', 1), ':', 2)`
	}
	return ""
}

// FindingCount is the number of findings with one value of the grouped dimension.
type FindingCount struct {
	Key   string
	Count int64
}

// CountFindings counts the findings of workloads that match filter, grouped by
// one dimension and ordered by key. Like ListFindings, it counts a finding once
// for every workload whose image has it.
func (db *DB) CountFindings(ctx context.Context, filter FindingFilter, groupBy GroupBy) ([]FindingCount, error) {
	if groupBy.key() == "" {
		return nil, fmt.Errorf("group by is required: %w", ErrInvalid)
	}
	var args sqlArgs
	where, err := filter.conditions(&args)
	if err != nil {
		return nil, err
	}
	if filter.OnlyKnownExploited {
		if err := db.requireKEVCatalog(ctx); err != nil {
			return nil, err
		}
	}
	return countFindings(ctx, db.pool, groupBy, where, args)
}

func countFindings(ctx context.Context, q pgxQuerier, groupBy GroupBy, where []string, args sqlArgs) ([]FindingCount, error) {
	rows, err := q.Query(ctx, `
		SELECT `+groupBy.key()+`, count(*)
		FROM `+findingsFrom+`
		WHERE `+and(where)+`
		GROUP BY 1 ORDER BY 1`, args...)
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

// vulnerabilityIDs returns the distinct vulnerability IDs idOrAlias names:
// itself if it is an ID, and every ID it is an alias of. It matches the same
// vulnerabilities as vulnerabilityMatch.
func vulnerabilityIDs(ctx context.Context, q pgxQuerier, idOrAlias string) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT id FROM vulnerabilities WHERE id = $1
		UNION
		SELECT vulnerability_id FROM vulnerability_aliases WHERE alias = $1
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

// VulnerabilityDetail is a vulnerability record with its EPSS score and CISA KEV membership.
type VulnerabilityDetail struct {
	v0s.Vulnerability
	EPSS           *v0s.EPSS
	KnownExploited bool // according to CISA KEV
}

// GetVulnerability returns the vulnerability named by an ID or an alias.
// A name that matches several vulnerabilities, as IDs or aliases, is ErrInvalid.
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
		return VulnerabilityDetail{}, fmt.Errorf("%q names several vulnerabilities (%s): %w", idOrAlias, strings.Join(ids, ", "), ErrInvalid)
	}
	if err := db.requireKEVCatalog(ctx); err != nil {
		return VulnerabilityDetail{}, err
	}

	var (
		d                       VulnerabilityDetail
		publishedAt, modifiedAt pgtype.Timestamptz
		epss                    epssScan
	)
	dest := []any{&d.ID, &d.Title, &d.Description, &d.Severities, &d.CVSS, &d.References, &publishedAt, &modifiedAt, &d.Aliases}
	dest = append(dest, epss.dest()...)
	dest = append(dest, &d.KnownExploited)
	err = db.pool.QueryRow(ctx, `
		SELECT v.id, v.title, v.description, v.severities, v.cvss, v."references", v.published_at, v.modified_at,
			ARRAY(SELECT alias FROM vulnerability_aliases WHERE vulnerability_id = v.id ORDER BY alias),
			e.score, e.date, k.cve IS NOT NULL
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
	return d, nil
}
