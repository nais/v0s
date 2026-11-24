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

func workloadOverviewOrders() []struct {
	name  string
	order database.WorkloadOrder
	want  []string
} {
	zero := []string{"e1/a/clean", "e1/a/failed", "e1/a/missing", "e1/a/pending", "e1/a/rescan-failed", "e1/a/scan-failed", "e1/a/unresolved"}
	return []struct {
		name  string
		order database.WorkloadOrder
		want  []string
	}{
		{"default", database.WorkloadOrder{}, []string{"e1/a/app", "e1/a/clean", "e1/a/failed", "e1/a/missing", "e1/a/pending", "e1/a/rescan-failed", "e1/a/scan-failed", "e1/a/unresolved", "e1/a/worker", "e1/b/app", "e2/a/app"}},
		{"findings ASC", database.WorkloadOrder{Field: database.WorkloadOrderFindingCount, Direction: database.FindingOrderASC}, append(slices.Clone(zero), "e1/b/app", "e2/a/app", "e1/a/app", "e1/a/worker")},
		{"findings DESC", database.WorkloadOrder{Field: database.WorkloadOrderFindingCount, Direction: database.FindingOrderDESC}, append([]string{"e1/a/worker", "e1/a/app", "e1/b/app", "e2/a/app"}, zero...)},
	}
}

func TestWorkloadOverviewCountsAndCoverage(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	list, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{}, database.WorkloadOverviewOptions{})
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
			list, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{}, database.WorkloadOverviewOptions{FindingFilter: tt.filter})
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
		options   database.WorkloadOverviewOptions
		total     int64
	}{
		{total: 11},
		{options: database.WorkloadOverviewOptions{AffectedOnly: true}, total: 4},
		{options: database.WorkloadOverviewOptions{FindingFilter: database.FindingFilter{PackageType: "missing"}}, total: 11},
		{options: database.WorkloadOverviewOptions{AffectedOnly: true, FindingFilter: database.FindingFilter{PackageType: "missing"}}, total: 0},
		{options: database.WorkloadOverviewOptions{AffectedOnly: true, FindingFilter: database.FindingFilter{Suppressed: database.SuppressedOnly}}, total: 1},
		{selection: database.WorkloadFilter{Teams: []string{"a"}}, total: 10},
		{selection: database.WorkloadFilter{Teams: []string{"a", "b", "a"}}, total: 11},
		{selection: database.WorkloadFilter{Teams: []string{"b"}}, total: 1},
		{selection: database.WorkloadFilter{Environment: "e1"}, total: 10},
		{selection: database.WorkloadFilter{Teams: []string{"a"}, Environment: "e1", Workload: "app"}, total: 1},
	} {
		list, err := db.ListWorkloadOverview(t.Context(), tt.selection, database.Page{}, tt.options)
		if err != nil || list.TotalCount != tt.total || int64(len(list.Workloads)) != tt.total {
			t.Fatalf("selection %+v / %+v: %+v, %v", tt.selection, tt.options, list, err)
		}
	}
	img2, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{Environment: "e2"}, database.Page{}, database.WorkloadOverviewOptions{FindingFilter: database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityUnknown}}})
	if err != nil || len(img2.Workloads) != 1 || img2.Workloads[0].Counts.SeverityCounts.Unknown != 2 || img2.Workloads[0].Counts.UniqueKEVVulnerabilityCount != 1 {
		t.Fatalf("UNKNOWN filter before per-workload aggregation: %+v, %v", img2, err)
	}
}

func TestWorkloadOverviewPaginationAndDeletion(t *testing.T) {
	for _, tt := range workloadOverviewOrders() {
		t.Run(tt.name, func(t *testing.T) {
			db := newWorkloadOverviewFixture(t)
			options := database.WorkloadOverviewOptions{Order: tt.order}
			for _, affected := range []bool{false, true} {
				options.AffectedOnly = affected
				want := slices.Clone(tt.want)
				if affected {
					want = slices.DeleteFunc(want, func(s string) bool {
						return s != "e1/a/app" && s != "e1/a/worker" && s != "e1/b/app" && s != "e2/a/app"
					})
				}
				for _, size := range []int{1, 2, 4} {
					page := database.Page{Size: size}
					var got []string
					for range 12 {
						list, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, page, options)
						if err != nil {
							t.Fatal(err)
						}
						if list.TotalCount != int64(len(want)) || len(list.Cursors) != len(list.Workloads) || len(list.Workloads) > size {
							t.Fatalf("page: %+v", list)
						}
						got = append(got, workloadOverviewKeys(list.Workloads)...)
						if list.NextPageToken == "" {
							break
						}
						if list.NextPageToken == page.Token || list.NextPageToken != list.Cursors[len(list.Cursors)-1] {
							t.Fatal("invalid next token")
						}
						page.Token = list.NextPageToken
					}
					if !slices.Equal(got, want) {
						t.Fatalf("size %d: %v, want %v", size, got, want)
					}
				}
				all, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{}, options)
				if err != nil {
					t.Fatal(err)
				}
				for i, token := range all.Cursors {
					list, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{Token: token}, options)
					if err != nil || !slices.Equal(workloadOverviewKeys(list.Workloads), want[i+1:]) || list.TotalCount != int64(len(want)) {
						t.Fatalf("row cursor %d: %+v, %v", i, list, err)
					}
				}
			}
			options.AffectedOnly = false
			all, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{}, options)
			if err != nil {
				t.Fatal(err)
			}
			boundary := all.Workloads[1].Workload
			if _, err := db.Pool().Exec(t.Context(), `DELETE FROM workloads WHERE environment=$1 AND team=$2 AND name=$3`, boundary.Environment, boundary.Team, boundary.Name); err != nil {
				t.Fatal(err)
			}
			resumed, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{Token: all.Cursors[1]}, options)
			if err != nil || resumed.TotalCount != 10 || !slices.Equal(workloadOverviewKeys(resumed.Workloads), tt.want[2:]) {
				t.Fatalf("deleted boundary: %+v, %v", resumed, err)
			}
		})
	}
}

func TestWorkloadOverviewCursorBinding(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	all, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{}, database.WorkloadOverviewOptions{})
	if err != nil {
		t.Fatal(err)
	}
	page := database.Page{Token: all.Cursors[0]}
	for _, selection := range []database.WorkloadFilter{
		{Teams: []string{"a"}}, {Environment: "e1"}, {Workload: "app"},
	} {
		if _, err := db.ListWorkloadOverview(t.Context(), selection, page, database.WorkloadOverviewOptions{}); !errors.Is(err, database.ErrInvalid) || !strings.Contains(err.Error(), "parameters changed") {
			t.Errorf("changed selection %+v: %v", selection, err)
		}
	}
	for _, filter := range []database.FindingFilter{
		{PackageType: "npm"}, {Package: "pkg:npm/d@1"}, {ImageName: "repo/app"}, {ImageDigest: "a"},
		{VulnerabilityIDs: []string{"D"}}, {Severities: []v0s.Severity{v0s.SeverityHigh}},
		{HasFix: true}, {OnlyKnownExploited: true}, {Suppressed: database.SuppressedInclude},
	} {
		if _, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, page, database.WorkloadOverviewOptions{FindingFilter: filter}); !errors.Is(err, database.ErrInvalid) {
			t.Errorf("changed finding filter %+v: %v", filter, err)
		}
	}
	if _, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, page, database.WorkloadOverviewOptions{AffectedOnly: true}); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("changed affected_only: %v", err)
	}
	for _, source := range workloadOverviewOrders() {
		list, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{}, database.WorkloadOverviewOptions{Order: source.order})
		if err != nil {
			t.Fatal(err)
		}
		for _, other := range workloadOverviewOrders() {
			if source.name == other.name {
				continue
			}
			if _, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{Token: list.Cursors[0]}, database.WorkloadOverviewOptions{Order: other.order}); !errors.Is(err, database.ErrInvalid) {
				t.Errorf("changed sort %s to %s: %v", source.name, other.name, err)
			}
		}
		data, err := base64.RawURLEncoding.DecodeString(list.Cursors[0])
		if err != nil {
			t.Fatal(err)
		}
		var cursor map[string]any
		if err := json.Unmarshal(data, &cursor); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"version", "operation", "binding", "environment", "team", "name", "finding_count"} {
			if _, ok := cursor[key]; !ok {
				continue
			}
			altered := make(map[string]any)
			for k, value := range cursor {
				altered[k] = value
			}
			delete(altered, key)
			if _, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{Token: encodeCursor(t, altered)}, database.WorkloadOverviewOptions{Order: source.order}); !errors.Is(err, database.ErrInvalid) {
				t.Errorf("missing cursor %s: %v", key, err)
			}
		}
	}
	legacy, next, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{}, database.Page{Size: 1})
	if err != nil || len(legacy) != 1 {
		t.Fatalf("legacy page: %+v, %v", legacy, err)
	}
	for _, token := range []string{next, "garbage!", encodeCursor(t, map[string]any{"version": 99}), base64.RawURLEncoding.EncodeToString([]byte(`null`))} {
		if _, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{Token: token}, database.WorkloadOverviewOptions{}); !errors.Is(err, database.ErrInvalid) {
			t.Errorf("invalid overview token %q: %v", token, err)
		}
	}
	if _, _, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{}, page); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("overview token in legacy listing: %v", err)
	}
	for _, f := range []database.FindingFilter{{Teams: []string{"a"}}, {Environment: "e1"}, {Workload: "app"}} {
		if _, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{}, database.WorkloadOverviewOptions{FindingFilter: f}); !errors.Is(err, database.ErrInvalid) {
			t.Errorf("competing scope: %v", err)
		}
	}
}

func TestWorkloadOverviewNormalizedCursor(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	selection := database.WorkloadFilter{Teams: []string{"b", "a", "a"}}
	options := database.WorkloadOverviewOptions{FindingFilter: database.FindingFilter{
		PackageType: "NPM", Package: "pkg:NPM/%64?arch=x", VulnerabilityIDs: []string{"D", "D"},
		Severities: []v0s.Severity{v0s.SeverityHigh, v0s.SeverityLow, v0s.SeverityHigh},
	}}
	all, err := db.ListWorkloadOverview(t.Context(), selection, database.Page{}, options)
	if err != nil || len(all.Cursors) < 2 {
		t.Fatalf("initial page: %+v, %v", all, err)
	}
	selection.Teams = []string{"a", "b"}
	options.FindingFilter.PackageType, options.FindingFilter.Package = "npm", "pkg:npm/d"
	options.FindingFilter.VulnerabilityIDs = []string{"D"}
	options.FindingFilter.Severities = []v0s.Severity{v0s.SeverityLow, v0s.SeverityHigh}
	options.Order = database.WorkloadOrder{Field: database.WorkloadOrderIdentity, Direction: database.FindingOrderASC}
	next, err := db.ListWorkloadOverview(t.Context(), selection, database.Page{Size: 1, Token: all.Cursors[0]}, options)
	if err != nil || len(next.Workloads) != 1 || !reflect.DeepEqual(next.Workloads[0], all.Workloads[1]) {
		t.Fatalf("normalized continuation: %+v, %v", next, err)
	}
	options.FindingFilter.VulnerabilityIDs = []string{"GHSA-D"}
	if _, err := db.ListWorkloadOverview(t.Context(), selection, database.Page{Token: all.Cursors[0]}, options); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("alias substitution: %v", err)
	}
}

func TestWorkloadOverviewKEVAndLegacyCursors(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	exec(t, db, `DELETE FROM kev`)
	if _, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{}, database.WorkloadOverviewOptions{}); !errors.Is(err, database.ErrUnavailable) {
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
