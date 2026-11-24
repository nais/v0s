package database_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/v0s"
)

func newWorkloadOverviewFixture(t *testing.T) *database.DB {
	t.Helper()
	db := newVulnerabilityFixture(t)
	exec(t, db, `
		UPDATE images SET sbom_state = 'fetched', sbom = '', scanned_at = '2026-01-02';
		INSERT INTO images (id, name, digest, sbom_state, sbom, scanned_at, error) OVERRIDING SYSTEM VALUE VALUES
			(3, 'repo/clean', 'c', 'fetched', '', '2026-01-02', ''),
			(4, 'repo/pending', 'd', 'pending', NULL, NULL, ''),
			(5, 'repo/failed', 'e', 'failed', NULL, NULL, 'fetch failed'),
			(6, 'repo/missing', 'f', 'missing', NULL, NULL, 'no attestation'),
			(7, 'repo/scan-failed', 'g', 'fetched', '', NULL, 'scan failed'),
			(8, 'repo/rescan-failed', 'h', 'fetched', '', '2026-01-02', 'rescan failed');
		INSERT INTO workloads (environment, team, name, image_reference, image_id)
		SELECT 'e1', 'a', substring(name from 6), name || ':1', id FROM images WHERE id > 2;
		INSERT INTO workloads (environment, team, name, image_reference, resolve_error)
		VALUES ('e1', 'a', 'unresolved', 'repo/unresolved:latest', 'tag not found');
		INSERT INTO kev (cve, date_added, known_ransomware_campaign) VALUES ('D', '2026-01-02', false);
		INSERT INTO suppressions (team, environment, workload, image_name, package_key, vulnerability_id, state, detail, updated_by)
		VALUES ('a', 'e1', 'app', 'repo/app', 'pkg:npm/d', 'D', 'accepted_risk', 'assessed', 'user');
	`)
	return db
}

func workloadOverviewKeys(rows []database.WorkloadOverview) []string {
	keys := make([]string, len(rows))
	for i, row := range rows {
		w := row.Workload
		keys[i] = w.Environment + "/" + w.Team + "/" + w.Name
	}
	return keys
}

func TestWorkloadOverviewCountsAndCoverage(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	list, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{}, database.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	legacy, _, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if list.TotalCount != 11 || len(list.Workloads) != len(legacy) {
		t.Fatalf("selection: %+v", list)
	}
	coverage := map[string]v0s.ImageStatus{
		"clean": v0s.ImageScanned, "failed": v0s.ImageFailed, "missing": v0s.ImageNoSBOM,
		"pending": v0s.ImagePending, "scan-failed": v0s.ImageFailed, "rescan-failed": v0s.ImageScanned,
	}
	for i, row := range list.Workloads {
		if !reflect.DeepEqual(row.Workload, legacy[i]) {
			t.Fatalf("coverage changed: %+v, want %+v", row.Workload, legacy[i])
		}
		c := row.Counts
		s := c.SeverityCounts
		if s.Critical+s.High+s.Medium+s.Low+s.Unknown != c.UniqueVulnerabilityCount {
			t.Fatalf("severity sum differs from unique count: %+v", row)
		}
		if status, ok := coverage[row.Workload.Name]; ok {
			if row.Workload.Image == nil || row.Workload.Image.Status() != status || c != (database.WorkloadFindingCounts{}) {
				t.Fatalf("zero-count coverage: %+v", row)
			}
			continue
		}
		if row.Workload.Name == "unresolved" {
			if row.Workload.Image != nil || row.Workload.ResolveError != "tag not found" || c != (database.WorkloadFindingCounts{}) {
				t.Fatalf("unresolved: %+v", row)
			}
			continue
		}
		want := database.WorkloadFindingCounts{
			FindingCount: 5, UniqueVulnerabilityCount: 4, UniqueKEVVulnerabilityCount: 2,
			SeverityCounts: database.VulnerabilitySeverityCounts{Critical: 1, Medium: 1, Low: 1, Unknown: 1},
		}
		if row.Workload.Image.ID == 1 {
			want.FindingCount, want.UniqueVulnerabilityCount = 7, 6
			want.SeverityCounts.High = 2
			if row.Workload.Name == "app" {
				want.FindingCount = 6
			}
		}
		if c != want {
			t.Fatalf("%s/%s/%s counts = %+v, want %+v", row.Workload.Environment, row.Workload.Team, row.Workload.Name, c, want)
		}
	}
}

func TestWorkloadOverviewFilters(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	for _, tt := range []struct {
		name   string
		filter database.FindingFilter
		counts database.WorkloadFindingCounts
	}{
		{"package type", database.FindingFilter{PackageType: "maven"}, database.WorkloadFindingCounts{FindingCount: 1, UniqueVulnerabilityCount: 1, SeverityCounts: database.VulnerabilitySeverityCounts{Unknown: 1}}},
		{"high", database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityHigh}}, database.WorkloadFindingCounts{FindingCount: 2, UniqueVulnerabilityCount: 2, SeverityCounts: database.VulnerabilitySeverityCounts{High: 2}, UniqueKEVVulnerabilityCount: 1}},
		{"low before grouping", database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityLow}}, database.WorkloadFindingCounts{FindingCount: 1, UniqueVulnerabilityCount: 1, SeverityCounts: database.VulnerabilitySeverityCounts{Low: 1}}},
		{"unknown before grouping", database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityUnknown}}, database.WorkloadFindingCounts{FindingCount: 1, UniqueVulnerabilityCount: 1, SeverityCounts: database.VulnerabilitySeverityCounts{Unknown: 1}}},
		{"KEV", database.FindingFilter{OnlyKnownExploited: true}, database.WorkloadFindingCounts{FindingCount: 2, UniqueVulnerabilityCount: 2, SeverityCounts: database.VulnerabilitySeverityCounts{Critical: 1, High: 1}, UniqueKEVVulnerabilityCount: 2}},
		{"fix", database.FindingFilter{HasFix: true}, database.WorkloadFindingCounts{FindingCount: 2, UniqueVulnerabilityCount: 2, SeverityCounts: database.VulnerabilitySeverityCounts{High: 1, Medium: 1}, UniqueKEVVulnerabilityCount: 1}},
		{"only assessments", database.FindingFilter{Suppressed: database.SuppressedOnly}, database.WorkloadFindingCounts{FindingCount: 1, UniqueVulnerabilityCount: 1, SeverityCounts: database.VulnerabilitySeverityCounts{High: 1}, UniqueKEVVulnerabilityCount: 1}},
		{"include assessments", database.FindingFilter{VulnerabilityIDs: []string{"D"}, Suppressed: database.SuppressedInclude}, database.WorkloadFindingCounts{FindingCount: 2, UniqueVulnerabilityCount: 1, SeverityCounts: database.VulnerabilitySeverityCounts{High: 1}, UniqueKEVVulnerabilityCount: 1}},
		{"aliases", database.FindingFilter{VulnerabilityIDs: []string{"GHSA-D", "D", "GHSA-SHARED", "F"}}, database.WorkloadFindingCounts{FindingCount: 2, UniqueVulnerabilityCount: 2, SeverityCounts: database.VulnerabilitySeverityCounts{High: 2}, UniqueKEVVulnerabilityCount: 1}},
		{"exact package suppressed", database.FindingFilter{Package: "pkg:npm/d@1"}, database.WorkloadFindingCounts{}},
		{"image mismatch", database.FindingFilter{ImageDigest: "b"}, database.WorkloadFindingCounts{}},
		{"image name mismatch", database.FindingFilter{ImageName: "repo/other"}, database.WorkloadFindingCounts{}},
		{"no matches", database.FindingFilter{VulnerabilityIDs: []string{"missing"}}, database.WorkloadFindingCounts{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			list, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{}, tt.filter)
			if err != nil {
				t.Fatal(err)
			}
			if list.TotalCount != 11 || len(list.Workloads) != 11 || list.Workloads[0].Counts != tt.counts {
				t.Fatalf("finding filter changed selection/counts: %+v, want first %+v", list, tt.counts)
			}
		})
	}
	for _, tt := range []struct {
		selection database.WorkloadFilter
		total     int64
	}{
		{selection: database.WorkloadFilter{Teams: []string{"a"}}, total: 10},
		{selection: database.WorkloadFilter{Teams: []string{"a", "b", "a"}}, total: 11},
		{selection: database.WorkloadFilter{Teams: []string{"b"}}, total: 1},
		{selection: database.WorkloadFilter{Environment: "e1"}, total: 10},
		{selection: database.WorkloadFilter{Teams: []string{"a"}, Environment: "e1", Workload: "app"}, total: 1},
	} {
		list, err := db.ListWorkloadOverview(t.Context(), tt.selection, database.Page{}, database.FindingFilter{})
		if err != nil || list.TotalCount != tt.total || int64(len(list.Workloads)) != tt.total {
			t.Fatalf("selection %+v: %+v, %v", tt.selection, list, err)
		}
	}
	img2, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{Environment: "e2"}, database.Page{}, database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityUnknown}})
	if err != nil || len(img2.Workloads) != 1 || img2.Workloads[0].Counts.SeverityCounts.Unknown != 2 || img2.Workloads[0].Counts.UniqueKEVVulnerabilityCount != 1 {
		t.Fatalf("UNKNOWN filter before per-workload aggregation: %+v, %v", img2, err)
	}
}

func TestWorkloadOverviewPaginationAndDeletion(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	want := []string{"e1/a/app", "e1/a/clean", "e1/a/failed", "e1/a/missing", "e1/a/pending", "e1/a/rescan-failed", "e1/a/scan-failed", "e1/a/unresolved", "e1/a/worker", "e1/b/app", "e2/a/app"}
	first, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{Size: 2}, database.FindingFilter{})
	if err != nil || first.TotalCount != int64(len(want)) || first.NextPageToken == "" || !slices.Equal(workloadOverviewKeys(first.Workloads), want[:2]) {
		t.Fatalf("first page: %+v, %v", first, err)
	}
	exec(t, db, `DELETE FROM workloads WHERE environment='e1' AND team='a' AND name='clean'`)
	page := database.Page{Token: first.NextPageToken}
	resumed, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, page, database.FindingFilter{})
	if err != nil || resumed.TotalCount != 10 || resumed.NextPageToken != "" || !slices.Equal(workloadOverviewKeys(resumed.Workloads), want[2:]) {
		t.Fatalf("deleted boundary: %+v, %v", resumed, err)
	}
	exec(t, db, `DELETE FROM workloads WHERE NOT (environment='e1' AND team='a' AND name='app')`)
	empty, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, page, database.FindingFilter{})
	if err != nil || empty.TotalCount != 1 || len(empty.Workloads) != 0 || empty.NextPageToken != "" {
		t.Fatalf("empty continuation: %+v, %v", empty, err)
	}
}

func TestWorkloadOverviewCursorBinding(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	all, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{Size: 1}, database.FindingFilter{})
	if err != nil || all.NextPageToken == "" {
		t.Fatalf("initial page: %+v, %v", all, err)
	}
	page := database.Page{Token: all.NextPageToken}
	for _, selection := range []database.WorkloadFilter{
		{Teams: []string{"a"}}, {Environment: "e1"}, {Workload: "app"},
	} {
		if _, err := db.ListWorkloadOverview(t.Context(), selection, page, database.FindingFilter{}); !errors.Is(err, database.ErrInvalid) || !strings.Contains(err.Error(), "restart pagination") {
			t.Errorf("changed selection %+v: %v", selection, err)
		}
	}
	for _, filter := range []database.FindingFilter{
		{PackageType: "npm"}, {Package: "pkg:npm/d@1"}, {ImageName: "repo/app"}, {ImageDigest: "a"},
		{VulnerabilityIDs: []string{"D"}}, {Severities: []v0s.Severity{v0s.SeverityHigh}},
		{HasFix: true}, {OnlyKnownExploited: true}, {Suppressed: database.SuppressedInclude},
	} {
		if _, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, page, filter); !errors.Is(err, database.ErrInvalid) {
			t.Errorf("changed finding filter %+v: %v", filter, err)
		}
	}
	data, err := base64.RawURLEncoding.DecodeString(page.Token)
	if err != nil {
		t.Fatal(err)
	}
	var cursor map[string]any
	if err := json.Unmarshal(data, &cursor); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"version", "operation", "binding", "e", "t", "w"} {
		value := cursor[key]
		delete(cursor, key)
		if _, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{Token: encodeCursor(t, cursor)}, database.FindingFilter{}); !errors.Is(err, database.ErrInvalid) {
			t.Errorf("missing cursor %s: %v", key, err)
		}
		cursor[key] = value
	}
	legacy, next, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{}, database.Page{Size: 1})
	if err != nil || len(legacy) != 1 {
		t.Fatalf("legacy page: %+v, %v", legacy, err)
	}
	for _, token := range []string{next, "garbage!", encodeCursor(t, map[string]any{"version": 99}), base64.RawURLEncoding.EncodeToString([]byte(`null`))} {
		if _, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{Token: token}, database.FindingFilter{}); !errors.Is(err, database.ErrInvalid) {
			t.Errorf("invalid overview token %q: %v", token, err)
		}
	}
	if _, _, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{}, page); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("overview token in legacy listing: %v", err)
	}
	for _, f := range []database.FindingFilter{{Teams: []string{"a"}}, {Environment: "e1"}, {Workload: "app"}} {
		if _, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{}, f); !errors.Is(err, database.ErrInvalid) {
			t.Errorf("competing scope: %v", err)
		}
	}
}

func TestWorkloadOverviewNormalizedCursor(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	selection := database.WorkloadFilter{Teams: []string{"b", "a", "a"}}
	filter := database.FindingFilter{
		PackageType: "NPM", Package: "pkg:NPM/%64?arch=x", VulnerabilityIDs: []string{"D", "D"},
		Severities: []v0s.Severity{v0s.SeverityHigh, v0s.SeverityLow, v0s.SeverityHigh},
	}
	first, err := db.ListWorkloadOverview(t.Context(), selection, database.Page{Size: 1}, filter)
	if err != nil || first.NextPageToken == "" {
		t.Fatalf("initial page: %+v, %v", first, err)
	}
	selection.Teams = []string{"a", "b"}
	filter.PackageType, filter.Package = "npm", "pkg:npm/d"
	filter.VulnerabilityIDs = []string{"D"}
	filter.Severities = []v0s.Severity{v0s.SeverityLow, v0s.SeverityHigh}
	next, err := db.ListWorkloadOverview(t.Context(), selection, database.Page{Size: 2, Token: first.NextPageToken}, filter)
	if err != nil || !slices.Equal(workloadOverviewKeys(next.Workloads), []string{"e1/a/clean", "e1/a/failed"}) {
		t.Fatalf("normalized continuation: %+v, %v", next, err)
	}
	filter.VulnerabilityIDs = []string{"GHSA-D"}
	if _, err := db.ListWorkloadOverview(t.Context(), selection, database.Page{Token: first.NextPageToken}, filter); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("alias substitution: %v", err)
	}
}

func TestWorkloadOverviewKEVAndLegacyCursors(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	exec(t, db, `DELETE FROM kev`)
	if _, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{}, database.FindingFilter{}); !errors.Is(err, database.ErrUnavailable) {
		t.Errorf("missing KEV catalog: %v", err)
	}
	all, _, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	var got []database.Workload
	page := database.Page{Size: 1}
	for range 12 {
		rows, next, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{}, page)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, rows...)
		if next == "" {
			break
		}
		wantToken := encodeCursor(t, struct {
			Environment string `json:"e"`
			Team        string `json:"t"`
			Name        string `json:"w"`
		}{rows[0].Environment, rows[0].Team, rows[0].Name})
		if next != wantToken {
			t.Fatalf("legacy cursor changed: %q, want %q", next, wantToken)
		}
		page.Token = next
	}
	if !reflect.DeepEqual(got, all) {
		t.Fatal("legacy traversal changed")
	}
}
