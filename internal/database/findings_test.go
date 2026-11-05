package database_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
)

// fixture is the data seedFixture writes:
//
//	repo/app@sha256:a runs in c1/team-a/app and c1/team-a/worker
//	repo/app@sha256:b runs in c1/team-b/other
//	repo/old@sha256:c runs nowhere
//
// CVE-1 has alias GHSA-1. GHSA-2 is an alias of both CVE-2 and CVE-3.
const fixture = `
INSERT INTO images (id, name, digest, sbom_state) OVERRIDING SYSTEM VALUE VALUES
	(1, 'repo/app', 'sha256:a', 'fetched'),
	(2, 'repo/app', 'sha256:b', 'fetched'),
	(3, 'repo/old', 'sha256:c', 'fetched');
INSERT INTO workload_images (environment, team, workload, image_id) VALUES
	('c1', 'team-a', 'app', 1),
	('c1', 'team-a', 'worker', 1),
	('c1', 'team-b', 'other', 2);
INSERT INTO vulnerabilities (id, title, cvss) VALUES
	('CVE-1', 'lodash bug', '{"nvd": {"v3_score": 7.5}, "ghsa": {"v3_score": 8.1}}'),
	('CVE-2', 'express bug', '{}'),
	('CVE-3', 'other bug', '{}');
INSERT INTO vulnerability_aliases (alias, vulnerability_id) VALUES
	('GHSA-1', 'CVE-1'), ('GHSA-2', 'CVE-2'), ('GHSA-2', 'CVE-3');
INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, fixed_version, status, severity) VALUES
	(1, 'CVE-1', 'pkg:npm/lodash@4.17.20', 'pkg:npm/lodash', '4.17.20', '4.17.21', 'fixed', 'HIGH'),
	(1, 'CVE-2', 'pkg:npm/express@4.0.0', 'pkg:npm/express', '4.0.0', '', 'affected', 'LOW'),
	(2, 'CVE-1', 'pkg:npm/lodash@4.17.19', 'pkg:npm/lodash', '4.17.19', '4.17.21', 'fixed', 'HIGH'),
	(3, 'CVE-1', 'pkg:npm/lodash@4.17.20', 'pkg:npm/lodash', '4.17.20', '4.17.21', 'fixed', 'HIGH');
INSERT INTO kev (cve, date_added, known_ransomware_campaign) VALUES ('CVE-2', '2026-01-02', true);
INSERT INTO components (image_id, purl, package_key, name, version) VALUES
	(1, 'pkg:npm/lodash@4.17.20', 'pkg:npm/lodash', 'lodash', '4.17.20'),
	(1, 'pkg:npm/left_pad@1.0.0', 'pkg:npm/left_pad', 'left_pad', '1.0.0'),
	(2, 'pkg:npm/lodash@4.17.19', 'pkg:npm/lodash', 'lodash', '4.17.19'),
	(3, 'pkg:npm/lodash@4.17.20', 'pkg:npm/lodash', 'lodash', '4.17.20');
`

// newFixture returns a database seeded with fixture and a function that runs more SQL against it.
func newFixture(t *testing.T) (*database.DB, func(sql string)) {
	t.Helper()
	db := databasetest.New(t)
	exec(t, db, fixture)
	return db, func(sql string) { t.Helper(); exec(t, db, sql) }
}

// findingKeys returns "digest vulnerability purl" for each finding.
func findingKeys(findings []database.ImageFinding) []string {
	keys := make([]string, 0, len(findings))
	for _, f := range findings {
		keys = append(keys, f.Image.Digest+" "+f.Finding.VulnerabilityID+" "+f.Finding.PURL)
	}
	return keys
}

const (
	aLodash  = "sha256:a CVE-1 pkg:npm/lodash@4.17.20"
	aExpress = "sha256:a CVE-2 pkg:npm/express@4.0.0"
	bLodash  = "sha256:b CVE-1 pkg:npm/lodash@4.17.19"
)

func TestListFindingsFilters(t *testing.T) {
	db, _ := newFixture(t)
	ctx := context.Background()

	tests := []struct {
		name   string
		filter database.FindingFilter
		want   []string
	}{
		{name: "only images in use", want: []string{aLodash, aExpress, bLodash}},
		{name: "vulnerability ID", filter: database.FindingFilter{VulnerabilityID: "CVE-1"}, want: []string{aLodash, bLodash}},
		{name: "vulnerability alias", filter: database.FindingFilter{VulnerabilityID: "GHSA-1"}, want: []string{aLodash, bLodash}},
		{name: "package key", filter: database.FindingFilter{Package: "pkg:npm/lodash"}, want: []string{aLodash, bLodash}},
		{name: "purl without version matches key", filter: database.FindingFilter{Package: "pkg:npm/lodash?arch=x"}, want: []string{aLodash, bLodash}},
		{name: "purl with version", filter: database.FindingFilter{Package: "pkg:npm/lodash@4.17.20"}, want: []string{aLodash}},
		{name: "purl with version in another spelling", filter: database.FindingFilter{Package: "pkg:NPM/%6Codash@4.17.20"}, want: []string{aLodash}},
		{name: "team", filter: database.FindingFilter{Teams: []string{"team-b"}}, want: []string{bLodash}},
		{name: "workload", filter: database.FindingFilter{Environment: "c1", Workload: "worker"}, want: []string{aLodash, aExpress}},
		{name: "image digest", filter: database.FindingFilter{ImageName: "repo/app", ImageDigest: "sha256:b"}, want: []string{bLodash}},
		{name: "severity", filter: database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityLow}}, want: []string{aExpress}},
		{name: "has fix", filter: database.FindingFilter{HasFix: true}, want: []string{aLodash, bLodash}},
		{name: "kev", filter: database.FindingFilter{KEV: true}, want: []string{aExpress}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, next, err := db.ListFindings(ctx, tt.filter, database.Page{})
			if err != nil {
				t.Fatal(err)
			}
			if got := findingKeys(findings); !slices.Equal(got, tt.want) {
				t.Errorf("findings = %q, want %q", got, tt.want)
			}
			if next != "" {
				t.Errorf("next page token = %q, want none", next)
			}
		})
	}

	t.Run("facts", func(t *testing.T) {
		findings, _, err := db.ListFindings(ctx, database.FindingFilter{VulnerabilityID: "CVE-1", ImageDigest: "sha256:a"}, database.Page{})
		if err != nil || len(findings) != 1 {
			t.Fatalf("ListFindings = %d findings, %v; want 1", len(findings), err)
		}
		f := findings[0]
		if f.CVSSScore != 8.1 || f.Title != "lodash bug" || f.KEV != nil || f.Suppressed || f.Suppressions != nil {
			t.Errorf("finding = cvss %v, title %q, kev %v, suppressed %v by %v; want 8.1, lodash bug, nil, not suppressed", f.CVSSScore, f.Title, f.KEV, f.Suppressed, f.Suppressions)
		}
	})

	t.Run("not a purl", func(t *testing.T) {
		_, _, err := db.ListFindings(ctx, database.FindingFilter{Package: "lodash"}, database.Page{})
		if !errors.Is(err, database.ErrInvalid) {
			t.Errorf("err = %v, want ErrInvalid", err)
		}
	})
}

func TestListFindingsPagination(t *testing.T) {
	db, _ := newFixture(t)
	ctx := context.Background()

	all, _, err := db.ListFindings(ctx, database.FindingFilter{}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	var (
		got  []database.ImageFinding
		page = database.Page{Size: 1}
	)
	for range 10 {
		findings, next, err := db.ListFindings(ctx, database.FindingFilter{}, page)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, findings...)
		if next == "" {
			break
		}
		page.Token = next
	}
	if !slices.Equal(findingKeys(got), findingKeys(all)) {
		t.Errorf("paged findings = %q, want %q", findingKeys(got), findingKeys(all))
	}

	if _, _, err := db.ListFindings(ctx, database.FindingFilter{}, database.Page{Token: "garbage!"}); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("malformed token: err = %v, want ErrInvalid", err)
	}
}

func TestCountFindings(t *testing.T) {
	db, _ := newFixture(t)
	ctx := context.Background()

	tests := []struct {
		groupBy database.GroupBy
		want    []database.FindingCount
	}{
		{groupBy: database.GroupBySeverity, want: []database.FindingCount{{Key: "HIGH", Count: 2}, {Key: "LOW", Count: 1}}},
		// sha256:a runs in two workloads, so its findings count twice.
		{groupBy: database.GroupByTeam, want: []database.FindingCount{{Key: "team-a", Count: 4}, {Key: "team-b", Count: 1}}},
		{groupBy: database.GroupByWorkload, want: []database.FindingCount{{Key: "c1/team-a/app", Count: 2}, {Key: "c1/team-a/worker", Count: 2}, {Key: "c1/team-b/other", Count: 1}}},
		{groupBy: database.GroupByImage, want: []database.FindingCount{{Key: "repo/app@sha256:a", Count: 2}, {Key: "repo/app@sha256:b", Count: 1}}},
		{groupBy: database.GroupByVulnerability, want: []database.FindingCount{{Key: "CVE-1", Count: 2}, {Key: "CVE-2", Count: 1}}},
	}
	for _, tt := range tests {
		got, err := db.CountFindings(ctx, database.FindingFilter{}, tt.groupBy)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(got, tt.want) {
			t.Errorf("CountFindings(group by %d) = %v, want %v", tt.groupBy, got, tt.want)
		}
	}

	if _, err := db.CountFindings(ctx, database.FindingFilter{}, 0); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("no group by: err = %v, want ErrInvalid", err)
	}
}

func TestSearchComponents(t *testing.T) {
	db, _ := newFixture(t)
	ctx := context.Background()

	tests := []struct {
		name   string
		filter database.ComponentFilter
		want   []string // "digest purl workloads..."
	}{
		{name: "package key", filter: database.ComponentFilter{Query: "pkg:npm/lodash"},
			want: []string{"sha256:a pkg:npm/lodash@4.17.20 app worker", "sha256:b pkg:npm/lodash@4.17.19 other"}},
		{name: "purl with version", filter: database.ComponentFilter{Query: "pkg:npm/lodash@4.17.19"},
			want: []string{"sha256:b pkg:npm/lodash@4.17.19 other"}},
		{name: "purl with version in another spelling", filter: database.ComponentFilter{Query: "pkg:NPM/%6Codash@4.17.19"},
			want: []string{"sha256:b pkg:npm/lodash@4.17.19 other"}},
		{name: "name prefix", filter: database.ComponentFilter{Query: "LOD", Teams: []string{"team-a"}},
			want: []string{"sha256:a pkg:npm/lodash@4.17.20 app worker"}},
		{name: "underscore is literal", filter: database.ComponentFilter{Query: "left_"},
			want: []string{"sha256:a pkg:npm/left_pad@1.0.0 app worker"}},
		{name: "underscore is not a wildcard", filter: database.ComponentFilter{Query: "lo_"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches, _, err := db.SearchComponents(ctx, tt.filter, database.Page{})
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, m := range matches {
				s := m.Image.Digest + " " + m.Component.PURL
				for _, w := range m.Workloads {
					s += " " + w.Name
				}
				got = append(got, s)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("matches = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestListWorkloads(t *testing.T) {
	db, _ := newFixture(t)
	ctx := context.Background()

	var (
		got  []string
		page = database.Page{Size: 2}
	)
	for range 10 {
		workloads, next, err := db.ListWorkloads(ctx, database.WorkloadFilter{Environment: "c1"}, page)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range workloads {
			got = append(got, w.Team+"/"+w.Name+" "+w.Image.Digest)
		}
		if next == "" {
			break
		}
		page.Token = next
	}
	want := []string{"team-a/app sha256:a", "team-a/worker sha256:a", "team-b/other sha256:b"}
	if !slices.Equal(got, want) {
		t.Errorf("workloads = %q, want %q", got, want)
	}
}

func TestListFindingEvents(t *testing.T) {
	db, exec := newFixture(t)
	ctx := context.Background()
	exec(`INSERT INTO finding_events (image_name, image_digest, vulnerability_id, purl, kind, db_version) VALUES
		('repo/app', 'sha256:a', 'CVE-1', 'pkg:npm/lodash@4.17.20', 'appeared', now()),
		('repo/app', 'sha256:b', 'CVE-1', 'pkg:npm/lodash@4.17.19', 'appeared', now()),
		('repo/app', 'sha256:a', 'CVE-2', 'pkg:npm/express@4.0.0', 'appeared', now()),
		('repo/old', 'sha256:c', 'CVE-1', 'pkg:npm/lodash@4.17.20', 'resolved', now())`)

	tests := []struct {
		name   string
		filter database.FindingEventFilter
		want   []int64
	}{
		{name: "all", want: []int64{1, 2, 3, 4}},
		{name: "alias", filter: database.FindingEventFilter{VulnerabilityID: "GHSA-1"}, want: []int64{1, 2, 4}},
		{name: "team", filter: database.FindingEventFilter{Teams: []string{"team-a"}}, want: []int64{1, 3}},
		{name: "image", filter: database.FindingEventFilter{ImageName: "repo/app", ImageDigest: "sha256:b"}, want: []int64{2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				got  []int64
				page = database.Page{Size: 1}
			)
			for range 10 {
				events, next, err := db.ListFindingEvents(ctx, tt.filter, page)
				if err != nil {
					t.Fatal(err)
				}
				for _, e := range events {
					got = append(got, e.ID)
				}
				if next == "" {
					break
				}
				page.Token = next
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("event IDs = %v, want %v", got, tt.want)
			}
		})
	}
}
