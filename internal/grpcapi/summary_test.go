package grpcapi_test

import (
	"slices"
	"testing"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestSummaryOverGRPC(t *testing.T) {
	client := serveVulnerabilities(t, newWorkloadOverviewServer(t))
	coverage := &v0sv1.WorkloadCoverage{TotalWorkloadCount: 9, ScannedCount: 5, PendingCount: 1, NoSbomCount: 1, FailedCount: 1, UnresolvedImageCount: 1}
	for _, tt := range []struct {
		name                                string
		filter                              *v0sv1.FindingFilter
		findings, unique, affected, kev, kw int64
		severity                            *v0sv1.VulnerabilitySeverityCounts
	}{
		{"all", nil, 11, 2, 4, 1, 4, &v0sv1.VulnerabilitySeverityCounts{High: 1, Unknown: 1}},
		{"severity before aggregation", &v0sv1.FindingFilter{Severities: []v0sv1.Severity{v0sv1.Severity_SEVERITY_LOW}}, 4, 1, 4, 0, 0, &v0sv1.VulnerabilitySeverityCounts{Low: 1}},
		{"KEV", &v0sv1.FindingFilter{OnlyKnownExploited: true}, 4, 1, 4, 1, 4, &v0sv1.VulnerabilitySeverityCounts{Unknown: 1}},
		{"fix", &v0sv1.FindingFilter{HasFix: true}, 4, 1, 4, 0, 0, &v0sv1.VulnerabilitySeverityCounts{Low: 1}},
		{"maven", &v0sv1.FindingFilter{PackageType: "maven"}, 4, 1, 4, 1, 4, &v0sv1.VulnerabilitySeverityCounts{Unknown: 1}},
		{"assessments", &v0sv1.FindingFilter{Suppressed: v0sv1.SuppressedFilter_SUPPRESSED_FILTER_ONLY}, 1, 1, 1, 0, 0, &v0sv1.VulnerabilitySeverityCounts{High: 1}},
		{"aliases", &v0sv1.FindingFilter{VulnerabilityIds: []string{"CVE-1", "GHSA-1", "CVE-1"}}, 7, 1, 4, 0, 0, &v0sv1.VulnerabilitySeverityCounts{High: 1}},
		{"no matches", &v0sv1.FindingFilter{PackageType: "missing"}, 0, 0, 0, 0, 0, &v0sv1.VulnerabilitySeverityCounts{}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.GetSummary(t.Context(), &v0sv1.GetSummaryRequest{FindingFilter: tt.filter})
			want := &v0sv1.GetSummaryResponse{
				FindingCount: tt.findings, UniqueVulnerabilityCount: tt.unique, AffectedWorkloadCount: tt.affected,
				SeverityCounts: tt.severity, UniqueKevVulnerabilityCount: tt.kev, KevAffectedWorkloadCount: tt.kw,
				Coverage: coverage,
			}
			if err != nil || !proto.Equal(got, want) {
				t.Fatalf("summary = %v, %v; want %v", got, err, want)
			}
		})
	}
	one, err := client.GetSummary(t.Context(), &v0sv1.GetSummaryRequest{Team: "team", Environment: "dev", Workload: "app"})
	if err != nil || one.GetFindingCount() != 2 || one.GetSeverityCounts().GetLow() != 1 || one.GetSeverityCounts().GetHigh() != 0 ||
		one.GetCoverage().GetTotalWorkloadCount() != 1 {
		t.Fatalf("workload-local severity differs from global severity: %v, %v", one, err)
	}
	clean, err := client.GetSummary(t.Context(), &v0sv1.GetSummaryRequest{Team: "team", Environment: "dev", Workload: "clean"})
	if err != nil || clean.GetFindingCount() != 0 || clean.GetUniqueVulnerabilityCount() != 0 ||
		clean.GetCoverage().GetTotalWorkloadCount() != 1 || clean.GetCoverage().GetScannedCount() != 1 {
		t.Fatalf("clean workload remains in coverage: %v, %v", clean, err)
	}
}

func TestSummaryGRPCSelection(t *testing.T) {
	client := workloadSelectorClient(t)
	for _, tt := range []struct {
		name                string
		req                 *v0sv1.GetSummaryRequest
		findings, unique    int64
		workloads, affected int64
	}{
		{"omitted", &v0sv1.GetSummaryRequest{}, 10, 3, 8, 6},
		{"empty", &v0sv1.GetSummaryRequest{WorkloadSelector: &v0sv1.WorkloadSelector{}}, 0, 0, 0, 0},
		{"explicit empty list", &v0sv1.GetSummaryRequest{WorkloadSelector: &v0sv1.WorkloadSelector{Workloads: []*v0sv1.WorkloadRef{}}}, 0, 0, 0, 0},
		{"selected across teams", &v0sv1.GetSummaryRequest{WorkloadSelector: apiWorkloadSelector()}, 5, 2, 5, 3},
		{"team intersection", &v0sv1.GetSummaryRequest{Team: "other", WorkloadSelector: apiWorkloadSelector()}, 2, 2, 1, 1},
		{"environment intersection", &v0sv1.GetSummaryRequest{Environment: "prod", WorkloadSelector: apiWorkloadSelector()}, 2, 2, 1, 1},
		{"disjoint scope", &v0sv1.GetSummaryRequest{Team: "other", Environment: "prod", WorkloadSelector: apiWorkloadSelector()}, 0, 0, 0, 0},
		{"unknown identity", &v0sv1.GetSummaryRequest{WorkloadSelector: &v0sv1.WorkloadSelector{Workloads: []*v0sv1.WorkloadRef{{Environment: "prod", Team: "team", Name: "unknown"}}}}, 0, 0, 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := client.GetSummary(t.Context(), tt.req)
			if err != nil || got.GetFindingCount() != tt.findings || got.GetUniqueVulnerabilityCount() != tt.unique ||
				got.GetAffectedWorkloadCount() != tt.affected || got.GetCoverage().GetTotalWorkloadCount() != tt.workloads {
				t.Fatalf("summary selection: %v, %v", got, err)
			}
			if got.GetCoverage() == nil || got.GetSeverityCounts() == nil {
				t.Fatal("empty summary messages must be present")
			}
			c := got.GetCoverage()
			if c.GetScannedCount()+c.GetPendingCount()+c.GetNoSbomCount()+c.GetFailedCount()+c.GetUnresolvedImageCount() != tt.workloads {
				t.Fatalf("coverage partition: %v", c)
			}
		})
	}
	selector := apiWorkloadSelector()
	want, err := client.GetSummary(t.Context(), &v0sv1.GetSummaryRequest{WorkloadSelector: selector})
	if err != nil {
		t.Fatal(err)
	}
	selector.Workloads = append(selector.Workloads, selector.Workloads...)
	slices.Reverse(selector.Workloads)
	got, err := client.GetSummary(t.Context(), &v0sv1.GetSummaryRequest{WorkloadSelector: selector})
	if err != nil || !proto.Equal(got, want) {
		t.Fatalf("normalized selection: %v, %v; want %v", got, err, want)
	}
}

func TestSummaryGRPCValidationAndUnavailable(t *testing.T) {
	client := serveVulnerabilities(t, newWorkloadOverviewServer(t))
	for _, req := range []*v0sv1.GetSummaryRequest{
		{Workload: "app"}, {Team: "team", Workload: "app"},
		{Team: "team", FindingFilter: &v0sv1.FindingFilter{Team: "team"}},
		{FindingFilter: &v0sv1.FindingFilter{Environment: "dev"}},
		{FindingFilter: &v0sv1.FindingFilter{Workload: "app"}},
		{FindingFilter: &v0sv1.FindingFilter{Severities: []v0sv1.Severity{0}}},
		{FindingFilter: &v0sv1.FindingFilter{Severities: []v0sv1.Severity{99}}},
		{FindingFilter: &v0sv1.FindingFilter{Suppressed: 99}},
		{FindingFilter: &v0sv1.FindingFilter{PackageType: "npm/no"}},
		{FindingFilter: &v0sv1.FindingFilter{Package: "invalid"}},
		{FindingFilter: &v0sv1.FindingFilter{VulnerabilityIds: []string{""}}},
		{WorkloadSelector: &v0sv1.WorkloadSelector{Workloads: []*v0sv1.WorkloadRef{nil}}},
		{WorkloadSelector: &v0sv1.WorkloadSelector{Workloads: []*v0sv1.WorkloadRef{{Team: "team", Name: "app"}}}},
	} {
		if resp, err := client.GetSummary(t.Context(), req); status.Code(err) != codes.InvalidArgument || resp != nil {
			t.Errorf("invalid summary request %v: %v, %v", req, resp, err)
		}
	}
	noKEV := serveVulnerabilities(t, newServer(t, `DELETE FROM kev`))
	for _, selector := range []*v0sv1.WorkloadSelector{nil, {}} {
		if resp, err := noKEV.GetSummary(t.Context(), &v0sv1.GetSummaryRequest{WorkloadSelector: selector}); status.Code(err) != codes.Unavailable || resp != nil {
			t.Errorf("missing KEV catalog: %v, %v", resp, err)
		}
	}
}
