package database_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
	"github.com/nais/v0s/internal/v0s"
)

// fixture is the data seedFixture writes:
//
//	repo/app@sha256:a runs in c1/team-a/app and c1/team-a/worker
//	repo/app@sha256:b runs in c1/team-b/other
//	repo/old@sha256:c runs nowhere
//
// CVE-1 has alias GHSA-1. GHSA-2 is an alias of both CVE-2 and CVE-3.
const fixture = `
INSERT INTO images (id, name, digest, sbom_state, sbom) OVERRIDING SYSTEM VALUE VALUES
	(1, 'repo/app', 'sha256:a', 'fetched', ''),
	(2, 'repo/app', 'sha256:b', 'fetched', ''),
	(3, 'repo/old', 'sha256:c', 'fetched', '');
INSERT INTO workloads (environment, team, name, image_reference, image_id) VALUES
	('c1', 'team-a', 'app', 'repo/app:1', 1),
	('c1', 'team-a', 'worker', 'repo/app:1', 1),
	('c1', 'team-b', 'other', 'repo/app:2', 2);
INSERT INTO vulnerabilities (id, title, db_version) VALUES
	('CVE-1', 'lodash bug', now()),
	('CVE-2', 'express bug', now()),
	('CVE-3', 'other bug', now());
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

func newPackageTypeFixture(t *testing.T) *database.DB {
	t.Helper()
	db, exec := newFixture(t)
	exec(`
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, status, severity) VALUES
			(1, 'CVE-3', 'pkg:maven/org.example/lib@1', 'pkg:maven/org.example/lib', '1', 'affected', 'HIGH'),
			(1, 'CVE-3', 'pkg:npm/%40scope/lib@1', 'pkg:npm/%40scope/lib', '1', 'affected', 'HIGH'),
			(2, 'CVE-3', 'pkg:golang/example.com/lib@1', 'pkg:golang/example.com/lib', '1', 'affected', 'HIGH'),
			(2, 'CVE-3', 'pkg:npm-tools/helper@1', 'pkg:npm-tools/helper', '1', 'affected', 'HIGH'),
			(2, 'CVE-3', 'pkg:kpm/helper@1', 'pkg:kpm/helper', '1', 'affected', 'HIGH');
	`)
	return db
}

// findingKeys returns "team/workload vulnerability purl" for each finding.
func findingKeys(findings []database.WorkloadFinding) []string {
	keys := make([]string, 0, len(findings))
	for _, f := range findings {
		keys = append(keys, f.Workload.Team+"/"+f.Workload.Name+" "+f.Finding.VulnerabilityID+" "+f.Finding.PURL)
	}
	return keys
}

const (
	appLodash     = "team-a/app CVE-1 pkg:npm/lodash@4.17.20"
	appExpress    = "team-a/app CVE-2 pkg:npm/express@4.0.0"
	workerLodash  = "team-a/worker CVE-1 pkg:npm/lodash@4.17.20"
	workerExpress = "team-a/worker CVE-2 pkg:npm/express@4.0.0"
	otherLodash   = "team-b/other CVE-1 pkg:npm/lodash@4.17.19"
	appMaven      = "team-a/app CVE-3 pkg:maven/org.example/lib@1"
	workerMaven   = "team-a/worker CVE-3 pkg:maven/org.example/lib@1"
	appScoped     = "team-a/app CVE-3 pkg:npm/%40scope/lib@1"
	workerScoped  = "team-a/worker CVE-3 pkg:npm/%40scope/lib@1"
	otherGo       = "team-b/other CVE-3 pkg:golang/example.com/lib@1"
	otherTools    = "team-b/other CVE-3 pkg:npm-tools/helper@1"
	otherKpm      = "team-b/other CVE-3 pkg:kpm/helper@1"
)

func TestListFindingsFilters(t *testing.T) {
	db, _ := newFixture(t)
	ctx := context.Background()

	tests := []struct {
		name   string
		filter database.FindingFilter
		want   []string
	}{
		// sha256:a runs in two workloads, so its findings are listed for each.
		{name: "every workload's findings", want: []string{appLodash, appExpress, workerLodash, workerExpress, otherLodash}},
		{name: "vulnerability ID", filter: database.FindingFilter{VulnerabilityIDs: []string{"CVE-1"}}, want: []string{appLodash, workerLodash, otherLodash}},
		{name: "vulnerability alias", filter: database.FindingFilter{VulnerabilityIDs: []string{"GHSA-1"}}, want: []string{appLodash, workerLodash, otherLodash}},
		{name: "IDs and overlapping aliases", filter: database.FindingFilter{
			VulnerabilityIDs: []string{"CVE-2", "GHSA-1", "CVE-1", "CVE-404"},
		}, want: []string{appLodash, appExpress, workerLodash, workerExpress, otherLodash}},
		{name: "package key", filter: database.FindingFilter{Package: "pkg:npm/lodash"}, want: []string{appLodash, workerLodash, otherLodash}},
		{name: "purl without version matches key", filter: database.FindingFilter{Package: "pkg:npm/lodash?arch=x"}, want: []string{appLodash, workerLodash, otherLodash}},
		{name: "purl with version", filter: database.FindingFilter{Package: "pkg:npm/lodash@4.17.20"}, want: []string{appLodash, workerLodash}},
		{name: "purl with version in another spelling", filter: database.FindingFilter{Package: "pkg:NPM/%6Codash@4.17.20"}, want: []string{appLodash, workerLodash}},
		{name: "team", filter: database.FindingFilter{Teams: []string{"team-b"}}, want: []string{otherLodash}},
		{name: "workload", filter: database.FindingFilter{Environment: "c1", Workload: "worker"}, want: []string{workerLodash, workerExpress}},
		{name: "image digest", filter: database.FindingFilter{ImageName: "repo/app", ImageDigest: "sha256:b"}, want: []string{otherLodash}},
		{name: "severity", filter: database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityLow}}, want: []string{appExpress, workerExpress}},
		{name: "has fix", filter: database.FindingFilter{HasFix: true}, want: []string{appLodash, workerLodash, otherLodash}},
		{name: "kev", filter: database.FindingFilter{OnlyKnownExploited: true}, want: []string{appExpress, workerExpress}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, err := db.ListFindings(ctx, tt.filter, database.Page{})
			if err != nil {
				t.Fatal(err)
			}
			if got := findingKeys(list.Findings); !slices.Equal(got, tt.want) {
				t.Errorf("findings = %q, want %q", got, tt.want)
			}
			if list.NextPageToken != "" {
				t.Errorf("next page token = %q, want none", list.NextPageToken)
			}
		})
	}

	t.Run("facts", func(t *testing.T) {
		list, err := db.ListFindings(ctx, database.FindingFilter{VulnerabilityIDs: []string{"CVE-1"}, Workload: "app"}, database.Page{})
		if err != nil || len(list.Findings) != 1 {
			t.Fatalf("ListFindings = %d findings, %v; want 1", len(list.Findings), err)
		}
		f := list.Findings[0]
		want := database.WorkloadRef{Environment: "c1", Team: "team-a", Name: "app"}
		if f.Workload != want || f.Image.Digest != "sha256:a" || f.KnownExploited || f.Suppression != nil {
			t.Errorf("finding = %+v, want in c1/team-a/app with sha256:a, not in CISA KEV, not suppressed", f)
		}
	})

	t.Run("not a purl", func(t *testing.T) {
		_, err := db.ListFindings(ctx, database.FindingFilter{Package: "lodash"}, database.Page{})
		if !errors.Is(err, database.ErrInvalid) {
			t.Errorf("err = %v, want ErrInvalid", err)
		}
	})
}

type packageTypeListCase struct {
	name    string
	filter  database.FindingFilter
	want    []string
	wantErr error
}

type packageTypeCountCase struct {
	name    string
	filter  database.FindingFilter
	want    []database.FindingCount
	wantErr error
}

func TestListFindingsPackageTypes(t *testing.T) {
	db := newPackageTypeFixture(t)
	ctx := context.Background()
	npm := []string{appLodash, appExpress, appScoped, workerLodash, workerExpress, workerScoped, otherLodash}
	all := append(slices.Clone(npm), appMaven, workerMaven, otherGo, otherTools, otherKpm)
	slices.Sort(all)
	tests := []packageTypeListCase{
		{name: "empty", want: all},
		{name: "npm", filter: database.FindingFilter{PackageType: "npm"}, want: npm},
		{name: "uppercase", filter: database.FindingFilter{PackageType: "NPM"}, want: npm},
		{name: "maven", filter: database.FindingFilter{PackageType: "maven"}, want: []string{appMaven, workerMaven}},
		{name: "golang", filter: database.FindingFilter{PackageType: "golang"}, want: []string{otherGo}},
		{name: "type boundary", filter: database.FindingFilter{PackageType: "npm-tools"}, want: []string{otherTools}},
		{name: "custom type", filter: database.FindingFilter{PackageType: "kpm"}, want: []string{otherKpm}},
		{name: "unknown", filter: database.FindingFilter{PackageType: "unknown"}},
		{name: "exact package", filter: database.FindingFilter{PackageType: "npm", Package: "pkg:npm/lodash@4.17.20"}, want: []string{appLodash, workerLodash}},
		{name: "conflicting package", filter: database.FindingFilter{PackageType: "maven", Package: "pkg:npm/lodash"}},
		{name: "severity", filter: database.FindingFilter{PackageType: "npm", Severities: []v0s.Severity{v0s.SeverityLow}}, want: []string{appExpress, workerExpress}},
		{name: "IDs and overlapping aliases", filter: database.FindingFilter{PackageType: "npm", VulnerabilityIDs: []string{"CVE-1", "GHSA-1", "CVE-3"}}, want: []string{appLodash, appScoped, workerLodash, workerScoped, otherLodash}},
		{name: "conflicting vulnerability", filter: database.FindingFilter{PackageType: "maven", VulnerabilityIDs: []string{"CVE-1"}}},
	}
	for _, typ := range []string{"npm/", "npm/%40scope", "npm%2F", "pkg:npm", "%", "_pm", " npm", "npm ", "n*m", "\u212Apm"} {
		tests = append(tests, packageTypeListCase{name: "invalid " + typ, filter: database.FindingFilter{PackageType: typ}, wantErr: database.ErrInvalid})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, err := db.ListFindings(ctx, tt.filter, database.Page{})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if got := findingKeys(list.Findings); !slices.Equal(got, tt.want) {
				t.Errorf("findings = %q, want %q", got, tt.want)
			}
			if list.NextPageToken != "" {
				t.Errorf("next page token = %q, want none", list.NextPageToken)
			}
		})
	}
}

func TestCountFindingsPackageTypes(t *testing.T) {
	db := newPackageTypeFixture(t)
	ctx := context.Background()
	tests := []packageTypeCountCase{
		{name: "empty", want: []database.FindingCount{{Key: "HIGH", Count: 10}, {Key: "LOW", Count: 2}}},
		{name: "npm", filter: database.FindingFilter{PackageType: "npm"}, want: []database.FindingCount{{Key: "HIGH", Count: 5}, {Key: "LOW", Count: 2}}},
		{name: "uppercase", filter: database.FindingFilter{PackageType: "MAVEN"}, want: []database.FindingCount{{Key: "HIGH", Count: 2}}},
		{name: "unknown", filter: database.FindingFilter{PackageType: "unknown"}},
		{name: "namespace is not a type", filter: database.FindingFilter{PackageType: "npm/%40scope"}, wantErr: database.ErrInvalid},
		{name: "exact package", filter: database.FindingFilter{PackageType: "npm", Package: "pkg:npm/lodash@4.17.20"}, want: []database.FindingCount{{Key: "HIGH", Count: 2}}},
		{name: "conflicting package", filter: database.FindingFilter{PackageType: "maven", Package: "pkg:npm/lodash"}},
		{name: "IDs and overlapping aliases", filter: database.FindingFilter{PackageType: "npm", VulnerabilityIDs: []string{"CVE-1", "GHSA-1", "CVE-3"}}, want: []database.FindingCount{{Key: "HIGH", Count: 5}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.CountFindings(ctx, tt.filter, database.GroupBySeverity)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("counts = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestListFindingsPackageTypeCounts(t *testing.T) {
	db := newPackageTypeFixture(t)
	exec(t, db, `
		INSERT INTO suppressions (team, environment, workload, image_name, package_key, vulnerability_id, state, detail, updated_by)
		VALUES ('team-a', 'c1', 'app', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'assessed', 'user');
	`)
	ctx := context.Background()
	tests := []packageTypeCountCase{
		{name: "every type, once per workload", want: []database.FindingCount{{Key: "golang", Count: 1}, {Key: "kpm", Count: 1}, {Key: "maven", Count: 2}, {Key: "npm", Count: 6}, {Key: "npm-tools", Count: 1}}},
		{name: "selected type", filter: database.FindingFilter{PackageType: "npm"}, want: []database.FindingCount{{Key: "npm", Count: 6}}},
		{name: "uppercase", filter: database.FindingFilter{PackageType: "MAVEN"}, want: []database.FindingCount{{Key: "maven", Count: 2}}},
		{name: "unknown type", filter: database.FindingFilter{PackageType: "unknown"}},
		{name: "team", filter: database.FindingFilter{Teams: []string{"team-b"}}, want: []database.FindingCount{{Key: "golang", Count: 1}, {Key: "kpm", Count: 1}, {Key: "npm", Count: 1}, {Key: "npm-tools", Count: 1}}},
		{name: "workload", filter: database.FindingFilter{Teams: []string{"team-a"}, Environment: "c1", Workload: "worker"}, want: []database.FindingCount{{Key: "maven", Count: 1}, {Key: "npm", Count: 3}}},
		{name: "other environment", filter: database.FindingFilter{Environment: "c2"}},
		{name: "image", filter: database.FindingFilter{ImageName: "repo/app", ImageDigest: "sha256:a"}, want: []database.FindingCount{{Key: "maven", Count: 2}, {Key: "npm", Count: 5}}},
		{name: "severity", filter: database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityLow}}, want: []database.FindingCount{{Key: "npm", Count: 2}}},
		{name: "exact package", filter: database.FindingFilter{Package: "pkg:npm/lodash@4.17.20"}, want: []database.FindingCount{{Key: "npm", Count: 1}}},
		{name: "conflicting package", filter: database.FindingFilter{PackageType: "maven", Package: "pkg:npm/lodash"}},
		{name: "vulnerability alias", filter: database.FindingFilter{VulnerabilityIDs: []string{"GHSA-1"}}, want: []database.FindingCount{{Key: "npm", Count: 2}}},
		{name: "IDs and overlapping aliases", filter: database.FindingFilter{PackageType: "npm", VulnerabilityIDs: []string{"CVE-1", "GHSA-1", "CVE-3"}}, want: []database.FindingCount{{Key: "npm", Count: 4}}},
		{name: "has fix", filter: database.FindingFilter{HasFix: true}, want: []database.FindingCount{{Key: "npm", Count: 2}}},
		{name: "kev", filter: database.FindingFilter{OnlyKnownExploited: true}, want: []database.FindingCount{{Key: "npm", Count: 2}}},
		{
			name: "combined filters",
			filter: database.FindingFilter{
				PackageType: "npm", Teams: []string{"team-a"}, Environment: "c1",
				Workload: "worker", Severities: []v0s.Severity{v0s.SeverityHigh},
			},
			want: []database.FindingCount{{Key: "npm", Count: 2}},
		},
		{name: "include suppressed", filter: database.FindingFilter{Suppressed: database.SuppressedInclude}, want: []database.FindingCount{{Key: "golang", Count: 1}, {Key: "kpm", Count: 1}, {Key: "maven", Count: 2}, {Key: "npm", Count: 7}, {Key: "npm-tools", Count: 1}}},
		{name: "only suppressed", filter: database.FindingFilter{Suppressed: database.SuppressedOnly}, want: []database.FindingCount{{Key: "npm", Count: 1}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			list, err := db.ListFindings(ctx, tt.filter, database.Page{Size: 1})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(list.PackageTypeCounts, tt.want) {
				t.Errorf("package type counts = %v, want %v", list.PackageTypeCounts, tt.want)
			}
			for _, count := range list.PackageTypeCounts {
				filter := tt.filter
				filter.PackageType = count.Key
				typed, err := db.ListFindings(ctx, filter, database.Page{})
				if err != nil {
					t.Fatal(err)
				}
				if int64(len(typed.Findings)) != count.Count || typed.NextPageToken != "" {
					t.Errorf("type %s: %d findings, next=%q; want %d and no next page", count.Key, len(typed.Findings), typed.NextPageToken, count.Count)
				}
			}
		})
	}
}

func TestListFindingsPackageTypeCountsByteOrder(t *testing.T) {
	db := newPackageTypeFixture(t)
	exec(t, db, `
		CREATE COLLATION punctuation_ignored (provider = icu, locale = 'und-u-ka-shifted');
		ALTER TABLE findings ALTER COLUMN package_key TYPE text COLLATE punctuation_ignored;
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, status, severity)
		VALUES (2, 'CVE-3', 'pkg:npmjs/helper@1', 'pkg:npmjs/helper', '1', 'affected', 'HIGH');
	`)
	list, err := db.ListFindings(context.Background(), database.FindingFilter{Teams: []string{"team-b"}}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	want := []database.FindingCount{{Key: "golang", Count: 1}, {Key: "kpm", Count: 1}, {Key: "npm", Count: 1}, {Key: "npm-tools", Count: 1}, {Key: "npmjs", Count: 1}}
	if !slices.Equal(list.PackageTypeCounts, want) {
		t.Errorf("package type counts = %v, want %v", list.PackageTypeCounts, want)
	}
}

func TestListFindingsPackageTypePagination(t *testing.T) {
	db := newPackageTypeFixture(t)
	ctx := context.Background()
	want := []string{appLodash, appExpress, appScoped, workerLodash, workerExpress, workerScoped, otherLodash}
	var (
		got  []database.WorkloadFinding
		page = database.Page{Size: 2}
	)
	for range len(want) + 1 {
		list, err := db.ListFindings(ctx, database.FindingFilter{PackageType: "npm"}, page)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(list.PackageTypeCounts, []database.FindingCount{{Key: "npm", Count: 7}}) {
			t.Errorf("package type counts = %v, want npm:7 on every page", list.PackageTypeCounts)
		}
		got = append(got, list.Findings...)
		if list.NextPageToken == "" {
			break
		}
		if list.NextPageToken == page.Token {
			t.Fatal("page token did not advance")
		}
		page.Token = list.NextPageToken
	}
	if !slices.Equal(findingKeys(got), want) {
		t.Errorf("paged findings = %q, want %q", findingKeys(got), want)
	}

	page.Token = base64.RawURLEncoding.EncodeToString([]byte(`{"e":"c1","t":"team-b","w":"other","v":"CVE-1","p":"pkg:npm/lodash@4.17.19"}`))
	list, err := db.ListFindings(ctx, database.FindingFilter{PackageType: "npm"}, page)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Findings) != 0 || list.NextPageToken != "" || !slices.Equal(list.PackageTypeCounts, []database.FindingCount{{Key: "npm", Count: 7}}) {
		t.Errorf("after last finding: %d findings, next=%q, counts=%v; want none, no token and npm:7", len(list.Findings), list.NextPageToken, list.PackageTypeCounts)
	}
}

func TestListFindingsPagination(t *testing.T) {
	db, _ := newFixture(t)
	ctx := context.Background()

	all, err := db.ListFindings(ctx, database.FindingFilter{}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	var (
		got  []database.WorkloadFinding
		page = database.Page{Size: 1}
	)
	for range 10 {
		list, err := db.ListFindings(ctx, database.FindingFilter{}, page)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, list.Findings...)
		if list.NextPageToken == "" {
			break
		}
		page.Token = list.NextPageToken
	}
	if !slices.Equal(findingKeys(got), findingKeys(all.Findings)) {
		t.Errorf("paged findings = %q, want %q", findingKeys(got), findingKeys(all.Findings))
	}

	if _, err := db.ListFindings(ctx, database.FindingFilter{}, database.Page{Token: "garbage!"}); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("malformed token: err = %v, want ErrInvalid", err)
	}
}

// TestListFindingsCursorBoundaries covers each part of the cursor, including two
// purls for the same advisory and images shared across environments and teams.
func TestListFindingsCursorBoundaries(t *testing.T) {
	db, exec := newFixture(t)
	exec(`
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, status, severity)
		VALUES (1, 'CVE-1', 'pkg:npm/lodash@4.17.19', 'pkg:npm/lodash', '4.17.19', 'affected', 'HIGH');
		INSERT INTO workloads (environment, team, name, image_reference, image_id)
		SELECT 'c' || e, 'team-' || t, 'app-' || lpad(n::text, 3, '0'), 'repo/app:1', 1
		FROM generate_series(1, 3) e CROSS JOIN generate_series(1, 3) t CROSS JOIN generate_series(1, 40) n;
		INSERT INTO workloads (environment, team, name, image_reference, resolve_error)
		VALUES ('c2', 'team-2', 'app-020a', 'repo/missing:1', 'not found');
		INSERT INTO suppressions (team, environment, workload, image_name, package_key, vulnerability_id, state, detail, updated_by)
		SELECT 'team-2', environment, name, 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'assessed', 'user'
		FROM workloads WHERE team = 'team-2';
		INSERT INTO epss (cve, score, percentile, date) VALUES ('CVE-1', 0.1, 0.9, '2026-01-02');
	`)
	ctx := context.Background()
	filters := []database.FindingFilter{
		{},
		{Suppressed: database.SuppressedInclude},
		{Suppressed: database.SuppressedOnly},
		{Environment: "c2", Teams: []string{"team-1", "team-2"}},
		{Workload: "app-020"},
		{ImageName: "repo/app", ImageDigest: "sha256:a"},
		{VulnerabilityIDs: []string{"GHSA-1"}},
		{Package: "pkg:npm/lodash@4.17.20"},
		{HasFix: true},
		{OnlyKnownExploited: true},
		{Severities: []v0s.Severity{v0s.SeverityLow}},
	}
	for i, filter := range filters {
		t.Run(fmt.Sprintf("filter_%d", i), func(t *testing.T) {
			// Use the original first-page query as the reference. Restrict its
			// environment so all reference results fit in a single page.
			if filter.Environment == "" {
				filter.Environment = "c2"
			}
			reference, err := db.ListFindings(ctx, filter, database.Page{Size: 1000})
			if err != nil || reference.NextPageToken != "" {
				t.Fatalf("reference page: next=%q, err=%v", reference.NextPageToken, err)
			}
			want := reference.Findings
			for _, size := range []int{1, 2, 7, 100} {
				var got []database.WorkloadFinding
				page := database.Page{Size: size}
				for range len(want) + 1 {
					list, err := db.ListFindings(ctx, filter, page)
					if err != nil {
						t.Fatal(err)
					}
					got = append(got, list.Findings...)
					if list.NextPageToken == "" {
						break
					}
					if list.NextPageToken == page.Token {
						t.Fatal("page token did not advance")
					}
					page.Token = list.NextPageToken
				}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("page size %d: paged findings differ from reference (%d rows, want %d)", size, len(got), len(want))
				}
			}
		})
	}

	// Traverse the full inventory across environment boundaries with page
	// boundaries inside workloads. Construct the expected order independently.
	var want []string
	for e := 1; e <= 3; e++ {
		for team := 1; team <= 3; team++ {
			for n := 1; n <= 40; n++ {
				prefix := fmt.Sprintf("c%d/team-%d/app-%03d ", e, team, n)
				want = append(want, prefix+"CVE-1 pkg:npm/lodash@4.17.19", prefix+"CVE-1 pkg:npm/lodash@4.17.20", prefix+"CVE-2 pkg:npm/express@4.0.0")
			}
		}
	}
	// Original fixture workloads sort after team-1/2/3 in c1.
	for _, key := range []string{appLodash, appExpress, workerLodash, workerExpress, otherLodash} {
		want = append(want, "c1/"+key)
	}
	want = append(want, "c1/team-a/app CVE-1 pkg:npm/lodash@4.17.19", "c1/team-a/worker CVE-1 pkg:npm/lodash@4.17.19")
	slices.Sort(want)
	var got []string
	page := database.Page{Size: 127}
	for range 20 {
		list, err := db.ListFindings(ctx, database.FindingFilter{Suppressed: database.SuppressedInclude}, page)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range list.Findings {
			got = append(got, f.Workload.Environment+"/"+f.Workload.Team+"/"+f.Workload.Name+" "+f.Finding.VulnerabilityID+" "+f.Finding.PURL)
		}
		if list.NextPageToken == "" {
			break
		}
		page.Token = list.NextPageToken
	}
	if !slices.Equal(got, want) {
		t.Errorf("full traversal differs from expected order: got %d rows, want %d", len(got), len(want))
	}
}

func TestCountFindings(t *testing.T) {
	db, _ := newFixture(t)
	ctx := context.Background()

	// Counts are of workload findings, as ListFindings lists them: sha256:a runs in two
	// workloads, so its findings count twice.
	tests := []struct {
		groupBy database.GroupBy
		want    []database.FindingCount
	}{
		{groupBy: database.GroupBySeverity, want: []database.FindingCount{{Key: "HIGH", Count: 3}, {Key: "LOW", Count: 2}}},
		{groupBy: database.GroupByTeam, want: []database.FindingCount{{Key: "team-a", Count: 4}, {Key: "team-b", Count: 1}}},
		{groupBy: database.GroupByWorkload, want: []database.FindingCount{{Key: "c1/team-a/app", Count: 2}, {Key: "c1/team-a/worker", Count: 2}, {Key: "c1/team-b/other", Count: 1}}},
		{groupBy: database.GroupByImage, want: []database.FindingCount{{Key: "repo/app@sha256:a", Count: 4}, {Key: "repo/app@sha256:b", Count: 1}}},
		{groupBy: database.GroupByVulnerability, want: []database.FindingCount{{Key: "CVE-1", Count: 3}, {Key: "CVE-2", Count: 2}}},
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

func TestGetVulnerability(t *testing.T) {
	db, _ := newFixture(t)
	ctx := context.Background()

	tests := []struct {
		idOrAlias string
		wantID    string
		wantErr   error
	}{
		{idOrAlias: "CVE-1", wantID: "CVE-1"},
		{idOrAlias: "GHSA-1", wantID: "CVE-1"},
		{idOrAlias: "GHSA-2", wantErr: database.ErrInvalid}, // an alias of both CVE-2 and CVE-3
		{idOrAlias: "CVE-404", wantErr: database.ErrNotFound},
	}
	for _, tt := range tests {
		v, err := db.GetVulnerability(ctx, tt.idOrAlias)
		if !errors.Is(err, tt.wantErr) || v.ID != tt.wantID {
			t.Errorf("GetVulnerability(%s) = %s, %v; want %s, %v", tt.idOrAlias, v.ID, err, tt.wantID, tt.wantErr)
		}
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
