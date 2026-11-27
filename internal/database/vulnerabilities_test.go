package database_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/v0s"
)

func newVulnerabilityFixture(t *testing.T) *database.DB {
	t.Helper()
	db := newOrderingFixture(t)
	exec(t, db, `
		DELETE FROM findings WHERE image_id = 2 AND vulnerability_id IN ('C', 'F');
		UPDATE findings SET severity = CASE WHEN purl = 'pkg:npm/d@1' THEN 'LOW' ELSE 'UNKNOWN' END
			WHERE image_id = 2 AND vulnerability_id = 'D';
		UPDATE findings SET fixed_version = '2' WHERE vulnerability_id = 'E'
			OR (image_id = 1 AND vulnerability_id = 'D');
		INSERT INTO vulnerability_aliases (alias, vulnerability_id) VALUES
			('GHSA-D', 'D'), ('GHSA-SHARED', 'D'), ('GHSA-SHARED', 'F');
	`)
	return db
}

func vulnerabilityOrders() []struct {
	name  string
	order database.VulnerabilityOrder
	want  []string
} {
	return []struct {
		name  string
		order database.VulnerabilityOrder
		want  []string
	}{
		{"default", database.VulnerabilityOrder{}, []string{"B", "D", "F", "E", "C", "A"}},
		{"severity ASC", database.VulnerabilityOrder{Field: database.VulnerabilityOrderSeverity, Direction: database.FindingOrderASC}, []string{"A", "C", "E", "D", "F", "B"}},
		{"severity DESC", database.VulnerabilityOrder{Field: database.VulnerabilityOrderSeverity, Direction: database.FindingOrderDESC}, []string{"B", "D", "F", "E", "C", "A"}},
		{"ID ASC", database.VulnerabilityOrder{Field: database.VulnerabilityOrderID, Direction: database.FindingOrderASC}, []string{"A", "B", "C", "D", "E", "F"}},
		{"ID DESC", database.VulnerabilityOrder{Field: database.VulnerabilityOrderID, Direction: database.FindingOrderDESC}, []string{"F", "E", "D", "C", "B", "A"}},
		{"workloads ASC", database.VulnerabilityOrder{Field: database.VulnerabilityOrderWorkloads, Direction: database.FindingOrderASC}, []string{"C", "F", "A", "B", "D", "E"}},
		{"workloads DESC", database.VulnerabilityOrder{Field: database.VulnerabilityOrderWorkloads, Direction: database.FindingOrderDESC}, []string{"A", "B", "D", "E", "C", "F"}},
	}
}

func vulnerabilityIDs(rows []database.VulnerabilitySummary) []string {
	ids := make([]string, len(rows))
	for i, v := range rows {
		ids[i] = v.VulnerabilityID
	}
	return ids
}

func TestListVulnerabilitiesOrdering(t *testing.T) {
	db := newVulnerabilityFixture(t)
	for _, tt := range vulnerabilityOrders() {
		t.Run(tt.name, func(t *testing.T) {
			for _, size := range []int{1, 2, 4} {
				var got []string
				page := database.Page{Size: size}
				for range 8 {
					list, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, page, tt.order)
					if err != nil {
						t.Fatal(err)
					}
					if list.TotalCount != 6 || len(list.Cursors) != len(list.Vulnerabilities) || len(list.Vulnerabilities) > size {
						t.Fatalf("unexpected page: %+v", list)
					}
					got = append(got, vulnerabilityIDs(list.Vulnerabilities)...)
					if list.NextPageToken == "" {
						break
					}
					if list.NextPageToken != list.Cursors[len(list.Cursors)-1] || list.NextPageToken == page.Token {
						t.Fatal("invalid next token")
					}
					page.Token = list.NextPageToken
				}
				if !slices.Equal(got, tt.want) {
					t.Fatalf("size %d: %v, want %v", size, got, tt.want)
				}
			}
			all, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{}, tt.order)
			if err != nil {
				t.Fatal(err)
			}
			for i, token := range all.Cursors {
				list, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{Token: token}, tt.order)
				if err != nil {
					t.Fatal(err)
				}
				if !slices.Equal(vulnerabilityIDs(list.Vulnerabilities), tt.want[i+1:]) || list.TotalCount != 6 {
					t.Fatalf("cursor %d: %+v", i, list)
				}
			}
		})
	}
}

func TestListVulnerabilitiesBidirectionalPagination(t *testing.T) {
	db := newVulnerabilityFixture(t)
	for _, tt := range vulnerabilityOrders() {
		t.Run(tt.name, func(t *testing.T) {
			all, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{}, tt.order)
			if err != nil {
				t.Fatal(err)
			}
			assertBidirectionalPages(t, all.Vulnerabilities, all.Cursors, func(page database.Page) ([]database.VulnerabilitySummary, []string, string, database.PageInfo, error) {
				list, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, page, tt.order)
				if err == nil && list.TotalCount != all.TotalCount {
					t.Fatalf("page changed total: %+v", list)
				}
				return list.Vulnerabilities, list.Cursors, list.NextPageToken, list.PageInfo, err
			})
			assertBidirectionalPages(t, []database.VulnerabilitySummary{}, nil, func(page database.Page) ([]database.VulnerabilitySummary, []string, string, database.PageInfo, error) {
				list, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{PackageType: "missing"}, page, tt.order)
				if list.TotalCount != 0 {
					t.Fatal("empty selection has nonzero total")
				}
				return list.Vulnerabilities, list.Cursors, list.NextPageToken, list.PageInfo, err
			})
		})
	}
}

func TestListVulnerabilitiesFiltersAndCounts(t *testing.T) {
	db := newVulnerabilityFixture(t)
	exec(t, db, `
		INSERT INTO suppressions (team, environment, workload, image_name, package_key, vulnerability_id, state, detail, updated_by)
		VALUES ('a', 'e1', 'app', 'repo/app', 'pkg:npm/d', 'D', 'accepted_risk', 'assessed', 'user');
	`)
	a := database.VulnerabilitySummary{VulnerabilityID: "A", Severity: v0s.SeverityUnknown, FindingCount: 4, AffectedWorkloadCount: 4}
	b := database.VulnerabilitySummary{VulnerabilityID: "B", Severity: v0s.SeverityCritical, FindingCount: 4, AffectedWorkloadCount: 4}
	c := database.VulnerabilitySummary{VulnerabilityID: "C", Severity: v0s.SeverityLow, FindingCount: 2, AffectedWorkloadCount: 2}
	d := database.VulnerabilitySummary{VulnerabilityID: "D", Severity: v0s.SeverityHigh, FindingCount: 7, AffectedWorkloadCount: 4}
	e := database.VulnerabilitySummary{VulnerabilityID: "E", Severity: v0s.SeverityMedium, FindingCount: 4, AffectedWorkloadCount: 4}
	f := database.VulnerabilitySummary{VulnerabilityID: "F", Severity: v0s.SeverityHigh, FindingCount: 2, AffectedWorkloadCount: 2}
	summary := func(severity v0s.Severity, findings, workloads int64) database.VulnerabilitySummary {
		return database.VulnerabilitySummary{VulnerabilityID: "D", Severity: severity, FindingCount: findings, AffectedWorkloadCount: workloads}
	}
	for _, tt := range []struct {
		name   string
		filter database.FindingFilter
		want   []database.VulnerabilitySummary
	}{
		{"default", database.FindingFilter{}, []database.VulnerabilitySummary{a, b, c, d, e, f}},
		{"npm", database.FindingFilter{PackageType: "NPM"}, []database.VulnerabilitySummary{b, c, d, e, f}},
		{"maven", database.FindingFilter{PackageType: "maven"}, []database.VulnerabilitySummary{a}},
		{"unknown package type", database.FindingFilter{PackageType: "missing"}, nil},
		{"KEV", database.FindingFilter{OnlyKnownExploited: true}, []database.VulnerabilitySummary{b}},
		{"fix", database.FindingFilter{HasFix: true}, []database.VulnerabilitySummary{summary(v0s.SeverityHigh, 3, 2), e}},
		{"include assessments", database.FindingFilter{VulnerabilityIDs: []string{"D"}, Suppressed: database.SuppressedInclude}, []database.VulnerabilitySummary{summary(v0s.SeverityHigh, 8, 4)}},
		{"only assessments", database.FindingFilter{Suppressed: database.SuppressedOnly}, []database.VulnerabilitySummary{summary(v0s.SeverityHigh, 1, 1)}},
		{"low before grouping", database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityLow}}, []database.VulnerabilitySummary{c, summary(v0s.SeverityLow, 2, 2)}},
		{"unknown before grouping", database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityUnknown}}, []database.VulnerabilitySummary{a, summary(v0s.SeverityUnknown, 2, 2)}},
		{"high before grouping", database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityHigh}}, []database.VulnerabilitySummary{summary(v0s.SeverityHigh, 3, 2), f}},
		{"aliases", database.FindingFilter{VulnerabilityIDs: []string{"GHSA-D", "D", "GHSA-SHARED", "F", "GHSA-D"}}, []database.VulnerabilitySummary{d, f}},
		{"exact package", database.FindingFilter{Package: "pkg:npm/d@1"}, []database.VulnerabilitySummary{summary(v0s.SeverityHigh, 3, 3)}},
		{"image digest", database.FindingFilter{ImageDigest: "b", VulnerabilityIDs: []string{"D"}}, []database.VulnerabilitySummary{summary(v0s.SeverityLow, 4, 2)}},
		{"scope", database.FindingFilter{Teams: []string{"a"}, Environment: "e1", Workload: "app", VulnerabilityIDs: []string{"D"}}, []database.VulnerabilitySummary{summary(v0s.SeverityHigh, 1, 1)}},
		{"combined", database.FindingFilter{PackageType: "npm", HasFix: true, Severities: []v0s.Severity{v0s.SeverityHigh}, Suppressed: database.SuppressedOnly}, []database.VulnerabilitySummary{summary(v0s.SeverityHigh, 1, 1)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			list, err := db.ListVulnerabilities(t.Context(), tt.filter, database.Page{}, database.VulnerabilityOrder{Field: database.VulnerabilityOrderID, Direction: database.FindingOrderASC})
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(list.Vulnerabilities, tt.want) || list.TotalCount != int64(len(tt.want)) {
				t.Fatalf("got %+v, want %+v", list, tt.want)
			}
		})
	}
	exec(t, db, `DELETE FROM kev`)
	if _, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{}, database.VulnerabilityOrder{}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{OnlyKnownExploited: true}, database.Page{}, database.VulnerabilityOrder{}); !errors.Is(err, database.ErrUnavailable) {
		t.Fatalf("missing KEV catalog: %v", err)
	}
}

func TestListVulnerabilitiesCursorDeletion(t *testing.T) {
	for _, tt := range vulnerabilityOrders() {
		t.Run(tt.name, func(t *testing.T) {
			db := newVulnerabilityFixture(t)
			all, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{}, tt.order)
			if err != nil {
				t.Fatal(err)
			}
			boundary := all.Vulnerabilities[2].VulnerabilityID
			if _, err := db.Pool().Exec(t.Context(), `DELETE FROM findings WHERE vulnerability_id=$1`, boundary); err != nil {
				t.Fatal(err)
			}
			list, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{Token: all.Cursors[2]}, tt.order)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(vulnerabilityIDs(list.Vulnerabilities), tt.want[3:]) || list.TotalCount != 5 {
				t.Fatalf("after deleting %s: %+v", boundary, list)
			}
			before, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{Token: all.Cursors[2], Direction: database.PageBackward}, tt.order)
			if err != nil || !slices.Equal(vulnerabilityIDs(before.Vulnerabilities), tt.want[:2]) || before.TotalCount != 5 {
				t.Fatalf("before deleted %s: %+v, %v", boundary, before, err)
			}
		})
	}
}

func TestListVulnerabilitiesCursorBinding(t *testing.T) {
	db := newVulnerabilityFixture(t)
	all, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{}, database.VulnerabilityOrder{})
	if err != nil {
		t.Fatal(err)
	}
	page := database.Page{Token: all.Cursors[0]}
	for _, filter := range []database.FindingFilter{
		{Teams: []string{"a"}}, {Environment: "e1"}, {Workload: "app"}, {ImageName: "repo/app"},
		{ImageDigest: "a"}, {Package: "pkg:npm/b"}, {PackageType: "npm"},
		{VulnerabilityIDs: []string{"B"}}, {Severities: []v0s.Severity{v0s.SeverityCritical}},
		{HasFix: true}, {OnlyKnownExploited: true}, {Suppressed: database.SuppressedInclude},
	} {
		for _, direction := range []database.PageDirection{database.PageForward, database.PageBackward} {
			page.Direction = direction
			if _, err := db.ListVulnerabilities(t.Context(), filter, page, database.VulnerabilityOrder{}); !errors.Is(err, database.ErrInvalid) || !strings.Contains(err.Error(), "filter or order") {
				t.Errorf("changed filter %+v: %v", filter, err)
			}
		}
	}
	for _, tt := range vulnerabilityOrders()[1:] {
		source, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{}, tt.order)
		if err != nil {
			t.Fatal(err)
		}
		for _, other := range vulnerabilityOrders()[1:] {
			if other.order == tt.order {
				continue
			}
			for _, direction := range []database.PageDirection{database.PageForward, database.PageBackward} {
				if _, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{Token: source.Cursors[0], Direction: direction}, other.order); !errors.Is(err, database.ErrInvalid) {
					t.Errorf("changed %s to %s: %v", tt.name, other.name, err)
				}
			}
		}
	}
	explicit := database.VulnerabilityOrder{Field: database.VulnerabilityOrderSeverity, Direction: database.FindingOrderDESC}
	if _, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, page, explicit); err != nil {
		t.Errorf("default to explicit sort: %v", err)
	}
	legacy, err := db.ListFindings(t.Context(), database.FindingFilter{}, database.Page{}, database.FindingOrder{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{Token: legacy.Cursors[0]}, database.VulnerabilityOrder{}); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("finding cursor accepted: %v", err)
	}
	if _, err := db.ListFindings(t.Context(), database.FindingFilter{}, page, database.FindingOrder{}); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("overview cursor accepted as finding: %v", err)
	}
	for _, token := range []string{"garbage!", encodeCursor(t, map[string]any{}), encodeCursor(t, map[string]any{"version": 99}), base64.RawURLEncoding.EncodeToString([]byte(`null`))} {
		if _, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{Token: token}, database.VulnerabilityOrder{}); !errors.Is(err, database.ErrInvalid) {
			t.Errorf("invalid token %q: %v", token, err)
		}
	}
	for _, tt := range vulnerabilityOrders()[1:] {
		source, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{}, tt.order)
		if err != nil {
			t.Fatal(err)
		}
		data, err := base64.RawURLEncoding.DecodeString(source.Cursors[0])
		if err != nil {
			t.Fatal(err)
		}
		var cursor map[string]any
		if err := json.Unmarshal(data, &cursor); err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{"id", "severity", "workloads"} {
			altered := make(map[string]any)
			for k, value := range cursor {
				altered[k] = value
			}
			if _, ok := altered[key]; !ok {
				continue
			}
			delete(altered, key)
			if _, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{Token: encodeCursor(t, altered)}, tt.order); !errors.Is(err, database.ErrInvalid) {
				t.Errorf("%s missing %s: %v", tt.name, key, err)
			}
		}
		invalid := map[string][]any{
			"version": {0, 99}, "operation": {"findings", ""}, "id": {""},
		}
		if tt.order.Field == database.VulnerabilityOrderSeverity {
			invalid["severity"] = []any{"", "INVALID"}
		}
		if tt.order.Field == database.VulnerabilityOrderWorkloads {
			invalid["workloads"] = []any{0, -1, nil}
		}
		for key, values := range invalid {
			for _, value := range values {
				altered := make(map[string]any)
				for k, v := range cursor {
					altered[k] = v
				}
				altered[key] = value
				if _, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, database.Page{Token: encodeCursor(t, altered)}, tt.order); !errors.Is(err, database.ErrInvalid) {
					t.Errorf("%s invalid %s=%v: %v", tt.name, key, value, err)
				}
			}
		}
	}
}

func encodeCursor(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

func TestListVulnerabilitiesNormalizedFilters(t *testing.T) {
	db := newVulnerabilityFixture(t)
	filter := database.FindingFilter{Teams: []string{"b", "a", "a"}, PackageType: "NPM",
		Package: "pkg:NPM/%64?arch=x", VulnerabilityIDs: []string{"D", "D"},
		Severities: []v0s.Severity{v0s.SeverityLow, v0s.SeverityHigh, v0s.SeverityLow}}
	all, err := db.ListVulnerabilities(t.Context(), filter, database.Page{}, database.VulnerabilityOrder{})
	if err != nil || len(all.Cursors) != 1 {
		t.Fatalf("initial page: %+v, %v", all, err)
	}
	filter.Teams = []string{"a", "b"}
	filter.PackageType = "npm"
	filter.Package = "pkg:npm/d"
	filter.VulnerabilityIDs = []string{"D"}
	filter.Severities = []v0s.Severity{v0s.SeverityHigh, v0s.SeverityLow}
	next, err := db.ListVulnerabilities(t.Context(), filter, database.Page{Size: 1, Token: all.Cursors[0]}, database.VulnerabilityOrder{})
	if err != nil || len(next.Vulnerabilities) != 0 || next.TotalCount != 1 {
		t.Fatalf("normalized continuation: %+v, %v", next, err)
	}
	filter.VulnerabilityIDs = []string{"GHSA-D"}
	if _, err := db.ListVulnerabilities(t.Context(), filter, database.Page{Token: all.Cursors[0]}, database.VulnerabilityOrder{}); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("alias substitution: %v", err)
	}
}

func TestListVulnerabilitiesIdentifierCollation(t *testing.T) {
	db := newVulnerabilityFixture(t)
	exec(t, db, `
		CREATE COLLATION punctuation_ignored (provider = icu, locale = 'und-u-ka-shifted');
		ALTER TABLE findings ALTER COLUMN vulnerability_id TYPE text COLLATE punctuation_ignored;
		DELETE FROM findings;
		INSERT INTO vulnerabilities (id, db_version) VALUES ('CVE-2', now()), ('CVE-10', now()), ('CVE_2', now()), ('cve-1', now());
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, status, severity)
		SELECT 1, id, 'pkg:npm/p@1', 'pkg:npm/p', '1', 'affected', 'HIGH'
		FROM vulnerabilities WHERE id IN ('CVE-2', 'CVE-10', 'CVE_2', 'cve-1');
	`)
	for _, tt := range vulnerabilityOrders()[1:] {
		want := []string{"CVE-10", "CVE-2", "CVE_2", "cve-1"}
		if tt.order.Field == database.VulnerabilityOrderID && tt.order.Direction == database.FindingOrderDESC {
			slices.Reverse(want)
		}
		var got []string
		page := database.Page{Size: 1}
		for range 5 {
			list, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, page, tt.order)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, vulnerabilityIDs(list.Vulnerabilities)...)
			if list.NextPageToken == "" {
				break
			}
			page.Token = list.NextPageToken
		}
		if !slices.Equal(got, want) {
			t.Errorf("%s: %v, want C byte order %v", tt.name, got, want)
		}
	}
}

func TestFindingBindingCompatibility(t *testing.T) {
	db, _ := newFixture(t)
	filter := database.FindingFilter{}
	order := database.FindingOrder{}
	data, err := json.Marshal(struct {
		Filter database.FindingFilter
		Order  database.FindingOrder
	}{filter, order})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	token := encodeCursor(t, map[string]any{
		"version": 1, "binding": hex.EncodeToString(sum[:]),
		"e": "c1", "t": "team-a", "w": "app", "v": "CVE-1", "p": "pkg:npm/lodash@4.17.20",
	})
	list, err := db.ListFindings(t.Context(), filter, database.Page{Token: token}, order)
	if err != nil || !slices.Equal(findingKeys(list.Findings), []string{appExpress, workerLodash, workerExpress, otherLodash}) {
		t.Fatalf("pre-overview finding cursor: %+v, %v", list, err)
	}
}
