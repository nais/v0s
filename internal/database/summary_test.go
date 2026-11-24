package database_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/v0s"
)

func TestSummaryGlobalCountsAndFilters(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	wantCoverage := database.WorkloadCoverage{TotalWorkloadCount: 11, ScannedCount: 6, PendingCount: 1, NoSBOMCount: 1, FailedCount: 2, UnresolvedImageCount: 1}
	for _, tt := range []struct {
		name                                string
		filter                              database.FindingFilter
		findings, unique, affected, kev, kw int64
		severity                            database.VulnerabilitySeverityCounts
	}{
		{"all", database.FindingFilter{}, 23, 6, 4, 2, 4, database.VulnerabilitySeverityCounts{Critical: 1, High: 2, Medium: 1, Low: 1, Unknown: 1}},
		{"high before aggregation", database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityHigh}}, 5, 2, 2, 1, 2, database.VulnerabilitySeverityCounts{High: 2}},
		{"low before aggregation", database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityLow}}, 4, 2, 4, 1, 2, database.VulnerabilitySeverityCounts{Low: 2}},
		{"unknown before aggregation", database.FindingFilter{Severities: []v0s.Severity{v0s.SeverityUnknown}}, 6, 2, 4, 1, 2, database.VulnerabilitySeverityCounts{Unknown: 2}},
		{"KEV", database.FindingFilter{OnlyKnownExploited: true}, 11, 2, 4, 2, 4, database.VulnerabilitySeverityCounts{Critical: 1, High: 1}},
		{"fix", database.FindingFilter{HasFix: true}, 7, 2, 4, 1, 2, database.VulnerabilitySeverityCounts{High: 1, Medium: 1}},
		{"assessments only", database.FindingFilter{Suppressed: database.SuppressedOnly}, 1, 1, 1, 1, 1, database.VulnerabilitySeverityCounts{High: 1}},
		{"include assessments", database.FindingFilter{Suppressed: database.SuppressedInclude}, 24, 6, 4, 2, 4, database.VulnerabilitySeverityCounts{Critical: 1, High: 2, Medium: 1, Low: 1, Unknown: 1}},
		{"npm", database.FindingFilter{PackageType: "NPM"}, 19, 5, 4, 2, 4, database.VulnerabilitySeverityCounts{Critical: 1, High: 2, Medium: 1, Low: 1}},
		{"maven", database.FindingFilter{PackageType: "maven"}, 4, 1, 4, 0, 0, database.VulnerabilitySeverityCounts{Unknown: 1}},
		{"overlapping aliases", database.FindingFilter{VulnerabilityIDs: []string{"D", "GHSA-D", "GHSA-SHARED", "F", "D"}}, 9, 2, 4, 1, 4, database.VulnerabilitySeverityCounts{High: 2}},
		{"exact package", database.FindingFilter{Package: "pkg:npm/d@1"}, 3, 1, 3, 1, 3, database.VulnerabilitySeverityCounts{High: 1}},
		{"image", database.FindingFilter{ImageDigest: "b"}, 10, 4, 2, 2, 2, database.VulnerabilitySeverityCounts{Critical: 1, Medium: 1, Low: 1, Unknown: 1}},
		{"no matches", database.FindingFilter{PackageType: "missing"}, 0, 0, 0, 0, 0, database.VulnerabilitySeverityCounts{}},
		{"image mismatch", database.FindingFilter{ImageName: "repo/unknown"}, 0, 0, 0, 0, 0, database.VulnerabilitySeverityCounts{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.GetSummary(t.Context(), database.WorkloadFilter{}, tt.filter)
			want := database.Summary{
				FindingCount: tt.findings, UniqueVulnerabilityCount: tt.unique, AffectedWorkloadCount: tt.affected,
				UniqueKEVVulnerabilityCount: tt.kev, KEVAffectedWorkloadCount: tt.kw,
				SeverityCounts: tt.severity, Coverage: wantCoverage,
			}
			if err != nil || got != want {
				t.Fatalf("summary = %+v, %v; want %+v", got, err, want)
			}
			s := got.SeverityCounts
			if s.Critical+s.High+s.Medium+s.Low+s.Unknown != got.UniqueVulnerabilityCount {
				t.Fatalf("severity sum: %+v", got)
			}
		})
	}
	overview, err := db.ListWorkloadOverview(t.Context(), database.WorkloadFilter{}, database.Page{}, database.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var perWorkload int64
	for _, row := range overview.Workloads {
		perWorkload += row.Counts.UniqueVulnerabilityCount
	}
	summary, err := db.GetSummary(t.Context(), database.WorkloadFilter{}, database.FindingFilter{})
	if err != nil || summary.UniqueVulnerabilityCount != 6 || perWorkload != 20 {
		t.Fatalf("global unique count must not be a per-workload sum: %+v, sum %d, %v", summary, perWorkload, err)
	}
}

func TestSummarySelection(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	for _, tt := range []struct {
		name                   string
		selection              database.WorkloadFilter
		findings, unique, rows int64
		affected               int64
	}{
		{"omitted", database.WorkloadFilter{}, 23, 6, 11, 4},
		{"empty", database.WorkloadFilter{Selector: &database.WorkloadSelector{}}, 0, 0, 0, 0},
		{"selected across teams", database.WorkloadFilter{Selector: selectedWorkloads()}, 16, 6, 5, 3},
		{"team", database.WorkloadFilter{Teams: []string{"b"}}, 5, 4, 1, 1},
		{"environment", database.WorkloadFilter{Environment: "e2"}, 5, 4, 1, 1},
		{"team and environment", database.WorkloadFilter{Teams: []string{"a"}, Environment: "e1"}, 13, 6, 9, 2},
		{"one workload", database.WorkloadFilter{Teams: []string{"a"}, Environment: "e1", Workload: "app"}, 6, 6, 1, 1},
		{"selector intersection", database.WorkloadFilter{Teams: []string{"a"}, Environment: "e1", Selector: selectedWorkloads()}, 6, 6, 3, 1},
		{"disjoint scope", database.WorkloadFilter{Environment: "e2", Teams: []string{"b"}, Selector: selectedWorkloads()}, 0, 0, 0, 0},
		{"no findings", database.WorkloadFilter{Environment: "e1", Teams: []string{"a"}, Workload: "clean"}, 0, 0, 1, 0},
		{"unknown", database.WorkloadFilter{Selector: &database.WorkloadSelector{Workloads: []database.WorkloadRef{{Environment: "e1", Team: "a", Name: "unknown"}}}}, 0, 0, 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := db.GetSummary(t.Context(), tt.selection, database.FindingFilter{})
			if err != nil || got.FindingCount != tt.findings || got.UniqueVulnerabilityCount != tt.unique ||
				got.Coverage.TotalWorkloadCount != tt.rows || got.AffectedWorkloadCount != tt.affected {
				t.Fatalf("summary: %+v, %v", got, err)
			}
			c := got.Coverage
			if c.ScannedCount+c.PendingCount+c.NoSBOMCount+c.FailedCount+c.UnresolvedImageCount != tt.rows {
				t.Fatalf("coverage partition: %+v", c)
			}
		})
	}
	selection := database.WorkloadFilter{Selector: selectedWorkloads()}
	want, err := db.GetSummary(t.Context(), selection, database.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	selection.Selector.Workloads = append(selection.Selector.Workloads, selection.Selector.Workloads...)
	slices.Reverse(selection.Selector.Workloads)
	if got, err := db.GetSummary(t.Context(), selection, database.FindingFilter{}); err != nil || got != want {
		t.Fatalf("duplicates/order changed summary: %+v, %v", got, err)
	}
	exec(t, db, `DELETE FROM workloads WHERE environment='e1' AND team='a' AND name='app'`)
	got, err := db.GetSummary(t.Context(), selection, database.FindingFilter{})
	if err != nil || got.FindingCount != 10 || got.UniqueVulnerabilityCount != 4 ||
		got.AffectedWorkloadCount != 2 || got.Coverage.TotalWorkloadCount != 4 {
		t.Fatalf("deleted workload in selector: %+v, %v", got, err)
	}
}

func TestSummaryCoverageStatusSemantics(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	exec(t, db, `
		INSERT INTO images (id, name, digest, sbom_state, sbom, scanned_at, error) OVERRIDING SYSTEM VALUE VALUES
			(9, 'repo/scan-pending', 'i', 'fetched', '', NULL, ''),
			(10, 'repo/fetch-pending', 'j', 'pending', NULL, '2026-01-02', 'fetch retry'),
			(11, 'repo/now-missing', 'k', 'missing', NULL, '2026-01-02', ''),
			(12, 'repo/now-failed', 'l', 'failed', NULL, '2026-01-02', 'fetch failed');
		INSERT INTO workloads (environment, team, name, image_reference, image_id)
		SELECT 'e1', 'a', substring(name from 6), name || ':1', id FROM images WHERE id > 8;
	`)
	workloads, _, err := db.ListWorkloads(t.Context(), database.WorkloadFilter{}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	var want database.WorkloadCoverage
	for _, w := range workloads {
		want.TotalWorkloadCount++
		if w.Image == nil {
			want.UnresolvedImageCount++
			continue
		}
		switch w.Image.Status() {
		case v0s.ImageScanned:
			want.ScannedCount++
		case v0s.ImagePending:
			want.PendingCount++
		case v0s.ImageNoSBOM:
			want.NoSBOMCount++
		case v0s.ImageFailed:
			want.FailedCount++
		}
	}
	got, err := db.GetSummary(t.Context(), database.WorkloadFilter{}, database.FindingFilter{})
	if err != nil || got.Coverage != want || got.Coverage.ScannedCount != 6 || got.Coverage.TotalWorkloadCount != 15 {
		t.Fatalf("summary coverage differs from existing image status: %+v, %v; want %+v", got, err, want)
	}
}

func TestSummaryInvalidFiltersAndKEV(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	for _, filter := range []database.FindingFilter{
		{Teams: []string{"a"}}, {Environment: "e1"}, {Workload: "app"}, {Selector: &database.WorkloadSelector{}},
		{Package: "invalid"}, {PackageType: "npm/bad"}, {Suppressed: 99},
	} {
		if _, err := db.GetSummary(t.Context(), database.WorkloadFilter{}, filter); !errors.Is(err, database.ErrInvalid) {
			t.Errorf("invalid filter %+v: %v", filter, err)
		}
	}
	if _, err := db.GetSummary(t.Context(), database.WorkloadFilter{Selector: &database.WorkloadSelector{Workloads: []database.WorkloadRef{{Team: "a"}}}}, database.FindingFilter{}); !errors.Is(err, database.ErrInvalid) {
		t.Errorf("incomplete selector: %v", err)
	}
	exec(t, db, `DELETE FROM kev`)
	for _, selector := range []*database.WorkloadSelector{nil, {}} {
		if result, err := db.GetSummary(t.Context(), database.WorkloadFilter{Selector: selector}, database.FindingFilter{}); !errors.Is(err, database.ErrUnavailable) || result != (database.Summary{}) {
			t.Errorf("missing catalog must not return success-shaped zeros: %+v, %v", result, err)
		}
	}
}

func TestSummarySnapshot(t *testing.T) {
	db := newWorkloadOverviewFixture(t)
	want, err := db.GetSummary(t.Context(), database.WorkloadFilter{}, database.FindingFilter{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	tx, err := db.Pool().Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE workloads IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	type result struct {
		summary database.Summary
		err     error
	}
	done := make(chan result, 1)
	go func() {
		summary, err := db.GetSummary(ctx, database.WorkloadFilter{}, database.FindingFilter{})
		done <- result{summary, err}
	}()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		var blocked bool
		if err := db.Pool().QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM pg_stat_activity
				WHERE datname = current_database() AND wait_event_type = 'Lock'
				AND query LIKE 'WITH selected AS (%')`).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM workloads; DELETE FROM findings; DELETE FROM kev`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-done:
		if got.err != nil || got.summary != want {
			t.Fatalf("catalog, findings and coverage used different snapshots: %+v, %v; want %+v", got.summary, got.err, want)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if _, err := db.GetSummary(t.Context(), database.WorkloadFilter{}, database.FindingFilter{}); !errors.Is(err, database.ErrUnavailable) {
		t.Fatalf("a new request must observe the missing catalog: %v", err)
	}
}
