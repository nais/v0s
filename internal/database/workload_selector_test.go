package database_test

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"github.com/nais/v0s/internal/database"
)

func TestWorkloadSelectorLegacyCursors(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	page := database.Page{Size: 1}
	_, legacy, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{}, page)
	if err != nil {
		t.Fatal(err)
	}
	findings, err := db.ListFindings(t.Context(), database.FindingFilter{}, page, database.FindingOrder{})
	if err != nil {
		t.Fatal(err)
	}
	vulnerabilities, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, page, database.VulnerabilityOrder{})
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct{ got, want string }{
		{legacy, "eyJlIjoiZTEiLCJ0IjoiYSIsInciOiJhcHAifQ"},
		{findings.NextPageToken, "eyJ2ZXJzaW9uIjoxLCJiaW5kaW5nIjoiNDVhODljMzc0OGU1NTg2YTk5YTE3NmRjNzQwNjExOWQ0ZDBhY2FjODk2MTliZDBiN2YzZmVmZDhiZTM4ZTI0NyIsImUiOiJlMSIsInQiOiJhIiwidyI6ImFwcCIsInYiOiJBIiwicCI6InBrZzptYXZlbi9hQDEifQ"},
		{vulnerabilities.NextPageToken, "eyJ2ZXJzaW9uIjoxLCJvcGVyYXRpb24iOiJ2dWxuZXJhYmlsaXRpZXMiLCJiaW5kaW5nIjoiODhjOWViZGExN2U4MGRmMzY3YTFlZWUzZDk1NzFlOGI5NTg0NWNiMzJiNWNlMmFlNDMxNTUyOGYyZDBiNDNkNiIsImlkIjoiQiIsInNldmVyaXR5IjoiQ1JJVElDQUwifQ"},
	} {
		if tt.got != tt.want {
			t.Errorf("cursor without selector changed: %q, want %q", tt.got, tt.want)
		}
	}
	page.Token = legacy
	if rows, _, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{}, page); err != nil || len(rows) != 1 || rows[0].Name != "clean" {
		t.Fatalf("legacy cursor continuation: %v, %v", rows, err)
	}
	page.Token = findings.NextPageToken
	if rows, err := db.ListFindings(t.Context(), database.FindingFilter{}, page, database.FindingOrder{}); err != nil || len(rows.Findings) != 1 || rows.Findings[0].Finding.VulnerabilityID != "B" {
		t.Fatalf("existing finding cursor continuation: %v, %v", rows, err)
	}
	page.Token = vulnerabilities.NextPageToken
	if rows, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{}, page, database.VulnerabilityOrder{}); err != nil || rows.TotalCount != 6 || len(rows.Vulnerabilities) != 1 {
		t.Fatalf("existing vulnerability cursor continuation: %v, %v", rows, err)
	}
}

func selectedWorkloads() *database.WorkloadSelector {
	return &database.WorkloadSelector{Workloads: []database.WorkloadRef{
		{Environment: "e2", Team: "a", Name: "app"},
		{Environment: "e1", Team: "b", Name: "app"},
		{Environment: "e1", Team: "a", Name: "clean"},
		{Environment: "e1", Team: "a", Name: "app"},
		{Environment: "e1", Team: "a", Name: "unresolved"},
	}}
}

func TestWorkloadSelectorSelection(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	for _, tt := range []struct {
		name                string
		selector            *database.WorkloadSelector
		workloads, findings int
	}{
		{"omitted", nil, 11, 23},
		{"empty", &database.WorkloadSelector{}, 0, 0},
		{"empty slice", &database.WorkloadSelector{Workloads: []database.WorkloadRef{}}, 0, 0},
		{"selected", selectedWorkloads(), 5, 16},
		{"unknown", &database.WorkloadSelector{Workloads: []database.WorkloadRef{{Environment: "e1", Team: "a", Name: "unknown"}}}, 0, 0},
		{"parameterized", &database.WorkloadSelector{Workloads: []database.WorkloadRef{{Environment: "e1", Team: "a", Name: "app') OR true --"}}}, 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			filter := database.FindingFilter{Selector: tt.selector}
			ws, _, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{Selector: tt.selector}, database.Page{})
			if err != nil || len(ws) != tt.workloads {
				t.Fatalf("workloads: %v, %v", ws, err)
			}
			findings, err := db.ListFindings(t.Context(), filter, database.Page{}, database.FindingOrder{})
			if err != nil || len(findings.Findings) != tt.findings {
				t.Fatalf("findings: %v, %v", findings, err)
			}
			counts, err := db.CountFindings(t.Context(), filter, database.GroupByWorkload)
			if err != nil {
				t.Fatal(err)
			}
			var total int64
			for _, c := range counts {
				total += c.Count
				if tt.selector != nil && c.Key == "e1/a/worker" {
					t.Fatal("selected by shared image instead of full identity")
				}
			}
			if total != int64(tt.findings) {
				t.Fatalf("counts: %v", counts)
			}
			vulns, err := db.ListVulnerabilities(t.Context(), filter, database.Page{}, database.VulnerabilityOrder{})
			if err != nil {
				t.Fatal(err)
			}
			var occurrences int64
			for _, v := range vulns.Vulnerabilities {
				occurrences += v.FindingCount
				if tt.name == "selected" && (v.VulnerabilityID == "A" || v.VulnerabilityID == "D") && v.AffectedWorkloadCount != 3 {
					t.Fatalf("shared images merged: %+v", v)
				}
			}
			if occurrences != total || (tt.findings == 0 && vulns.TotalCount != 0) || (tt.findings != 0 && vulns.TotalCount != 6) {
				t.Fatalf("vulnerabilities: %+v", vulns)
			}
			overview, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{Selector: tt.selector}, database.Page{}, database.FindingFilter{})
			if err != nil || len(overview.Workloads) != tt.workloads || overview.TotalCount != int64(tt.workloads) {
				t.Fatalf("overview: %+v, %v", overview, err)
			}
			var findingsTotal int64
			for _, w := range overview.Workloads {
				findingsTotal += w.Counts.FindingCount
			}
			if findingsTotal != total {
				t.Fatalf("overview counts: %d, want %d", findingsTotal, total)
			}
		})
	}
}

func TestWorkloadSelectorIntersectionsAndPages(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	selector := selectedWorkloads()
	for _, tt := range []struct {
		filter database.FindingFilter
		count  int
		unique int64
	}{
		{database.FindingFilter{Teams: []string{"a"}, Environment: "e1"}, 6, 6},
		{database.FindingFilter{Teams: []string{"b"}, Environment: "e2"}, 0, 0},
		{database.FindingFilter{Teams: []string{"a"}, Environment: "e1", Workload: "worker"}, 0, 0},
		{database.FindingFilter{PackageType: "maven"}, 3, 1},
		{database.FindingFilter{VulnerabilityIDs: []string{"GHSA-D"}}, 5, 1},
		{database.FindingFilter{OnlyKnownExploited: true}, 8, 2},
		{database.FindingFilter{HasFix: true}, 4, 2},
		{database.FindingFilter{Suppressed: database.SuppressedOnly}, 1, 1},
	} {
		tt.filter.Selector = selector
		for _, order := range []database.FindingOrder{{}, {Field: database.FindingOrderSeverity, Direction: database.FindingOrderDESC}} {
			page := database.Page{Size: 2}
			var got []string
			var expectedFacets []database.FindingCount
			for i := 0; i < 20; i++ {
				list, err := db.ListFindings(t.Context(), tt.filter, page, order)
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					expectedFacets = list.PackageTypeCounts
				}
				if !reflect.DeepEqual(list.PackageTypeCounts, expectedFacets) {
					t.Fatal("facets changed between pages")
				}
				var facetsTotal int64
				for _, c := range list.PackageTypeCounts {
					facetsTotal += c.Count
				}
				if facetsTotal != int64(tt.count) {
					t.Fatalf("full-selection facets: %v, want total %d", list.PackageTypeCounts, tt.count)
				}
				got = append(got, orderedFindingKeys(list.Findings)...)
				if len(list.Findings) == 0 {
					break
				}
				page.Token = list.Cursors[len(list.Cursors)-1]
			}
			if len(got) != tt.count || len(slices.Compact(slices.Sorted(slices.Values(got)))) != tt.count {
				t.Fatalf("pages: %v, want %d distinct findings", got, tt.count)
			}
		}
		counts, err := db.CountFindings(t.Context(), tt.filter, database.GroupByPackageType)
		if err != nil {
			t.Fatal(err)
		}
		var count int64
		for _, c := range counts {
			count += c.Count
		}
		if count != int64(tt.count) {
			t.Fatalf("count intersection: %v", counts)
		}
		for _, order := range []database.VulnerabilityOrder{{}, {Field: database.VulnerabilityOrderWorkloads, Direction: database.FindingOrderDESC}} {
			page := database.Page{Size: 1}
			var got []string
			for range 8 {
				list, err := db.ListVulnerabilities(t.Context(), tt.filter, page, order)
				if err != nil || list.TotalCount != tt.unique {
					t.Fatalf("full total: %+v, %v, want %d", list, err, tt.unique)
				}
				got = append(got, vulnerabilityIDs(list.Vulnerabilities)...)
				if len(list.Cursors) == 0 {
					break
				}
				page.Token = list.Cursors[len(list.Cursors)-1]
			}
			if len(got) != int(tt.unique) || len(slices.Compact(slices.Sorted(slices.Values(got)))) != int(tt.unique) {
				t.Fatalf("vulnerability pages: %v", got)
			}
		}
	}
	for _, packageType := range []string{"", "missing"} {
		page := database.Page{Size: 1}
		var got []string
		for range 6 {
			list, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{Selector: selector}, page, database.FindingFilter{PackageType: packageType})
			if err != nil || list.TotalCount != 5 || len(list.Workloads) != 1 {
				t.Fatalf("overview page: %+v, %v", list, err)
			}
			got = append(got, workloadOverviewKeys(list.Workloads)...)
			if packageType == "missing" && list.Workloads[0].Counts.FindingCount != 0 {
				t.Fatal("filter with zero matches did not clear counts")
			}
			page.Token = list.NextPageToken
			if page.Token == "" {
				break
			}
		}
		if len(got) != 5 || len(slices.Compact(slices.Sorted(slices.Values(got)))) != 5 || page.Token != "" {
			t.Fatalf("overview traversal: %v", got)
		}
	}
	ws, _, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{Teams: []string{"a"}, Environment: "e1", Selector: selector}, database.Page{})
	if err != nil || len(ws) != 3 {
		t.Fatalf("workload scope intersection: %v, %v", ws, err)
	}
}

func TestWorkloadSelectorCursorsAndValidation(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	for _, tt := range []struct {
		name string
		list func(*database.WorkloadSelector, string) (string, error)
	}{
		{"workloads", func(s *database.WorkloadSelector, token string) (string, error) {
			_, next, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{Selector: s}, database.Page{Size: 1, Token: token})
			return next, err
		}},
		{"findings", func(s *database.WorkloadSelector, token string) (string, error) {
			list, err := db.ListFindings(t.Context(), database.FindingFilter{Selector: s}, database.Page{Size: 1, Token: token}, database.FindingOrder{})
			return list.NextPageToken, err
		}},
		{"vulnerabilities", func(s *database.WorkloadSelector, token string) (string, error) {
			list, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{Selector: s}, database.Page{Size: 1, Token: token}, database.VulnerabilityOrder{})
			return list.NextPageToken, err
		}},
		{"overview", func(s *database.WorkloadSelector, token string) (string, error) {
			list, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{Selector: s}, database.Page{Size: 1, Token: token}, database.FindingFilter{})
			return list.NextPageToken, err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			selector := selectedWorkloads()
			first, err := tt.list(selector, "")
			if err != nil || first == "" {
				t.Fatalf("first token: %q, %v", first, err)
			}
			want, err := tt.list(selector, first)
			if err != nil {
				t.Fatal(err)
			}
			selector.Workloads = append(selector.Workloads, selector.Workloads...)
			slices.Reverse(selector.Workloads)
			if got, err := tt.list(selector, first); err != nil || got != want {
				t.Fatalf("normalized continuation: %q, %v, want %q", got, err, want)
			}
			changed := selectedWorkloads()
			changed.Workloads = append(changed.Workloads, database.WorkloadRef{Environment: "e1", Team: "a", Name: "unknown"})
			for _, s := range []*database.WorkloadSelector{nil, {}, changed} {
				if _, err := tt.list(s, first); !errors.Is(err, database.ErrInvalid) {
					t.Errorf("changed selector accepted: %v", err)
				}
			}
			old, err := tt.list(nil, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tt.list(selector, old); !errors.Is(err, database.ErrInvalid) {
				t.Errorf("unselected cursor accepted with selector: %v", err)
			}
			for _, w := range []database.WorkloadRef{
				{}, {Environment: "e1", Team: "a"}, {Environment: "e1", Name: "app"},
				{Team: "a", Name: "app"}, {Environment: " ", Team: "a", Name: "app"},
			} {
				invalid := &database.WorkloadSelector{Workloads: []database.WorkloadRef{w}}
				if _, err := tt.list(invalid, ""); !errors.Is(err, database.ErrInvalid) {
					t.Errorf("invalid identity accepted: %+v, %v", w, err)
				}
				if _, err := db.CountFindings(t.Context(), database.FindingFilter{Selector: invalid}, database.GroupByTeam); !errors.Is(err, database.ErrInvalid) {
					t.Errorf("invalid identity in counts: %v", err)
				}
			}
		})
	}
	selector := selectedWorkloads()
	_, token, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{Selector: selector}, database.Page{Size: 1})
	if err != nil {
		t.Fatal(err)
	}
	exec(t, db, `DELETE FROM workloads WHERE environment='e1' AND team='a' AND name='app'`)
	rows, _, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{Selector: selector}, database.Page{Token: token})
	if err != nil || len(rows) != 4 || rows[0].Name != "clean" {
		t.Fatalf("deleted boundary: %v, %v", rows, err)
	}
	vulns, err := db.ListVulnerabilities(t.Context(), database.FindingFilter{Selector: selector}, database.Page{}, database.VulnerabilityOrder{})
	if err != nil || vulns.TotalCount != 4 {
		t.Fatalf("deleted selection entry: %+v, %v", vulns, err)
	}
	if _, _, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{Environment: "e1", Selector: selector}, database.Page{Token: token}); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("changed scope with selector accepted: %v", err)
	}
}

func TestWorkloadSelectorLargeSelection(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	selector := &database.WorkloadSelector{}
	for i := range 25_000 {
		selector.Workloads = append(selector.Workloads, database.WorkloadRef{Environment: "e1", Team: "a", Name: fmt.Sprintf("unknown-%05d", i)})
	}
	selector.Workloads = append(selector.Workloads, selectedWorkloads().Workloads...)
	ws, _, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{Selector: selector}, database.Page{})
	if err != nil || len(ws) != 5 {
		t.Fatalf("large workload selection: %d, %v", len(ws), err)
	}
	list, err := db.ListFindings(t.Context(), database.FindingFilter{Selector: selector}, database.Page{Size: 1}, database.FindingOrder{})
	if err != nil || len(list.Findings) != 1 || !reflect.DeepEqual(list.PackageTypeCounts, []database.FindingCount{{Key: "maven", Count: 3}, {Key: "npm", Count: 13}}) {
		t.Fatalf("large finding selection: %+v, %v", list, err)
	}
}
