package grpcapi

import (
	"context"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/database"
)

func (s *Server) GetSummary(ctx context.Context, req *v0sv1.GetSummaryRequest) (*v0sv1.GetSummaryResponse, error) {
	if err := validateScope(req.GetTeam(), req.GetEnvironment(), req.GetWorkload()); err != nil {
		return nil, err
	}
	filter, err := unscopedFindingFilter(req.GetFindingFilter(), "finding_filter")
	if err != nil {
		return nil, err
	}
	selection := database.WorkloadFilter{
		Teams: teamFilter(req.GetTeam()), Environment: req.GetEnvironment(), Workload: req.GetWorkload(),
		Selector: workloadSelector(req.GetWorkloadSelector()),
	}
	summary, err := s.db.GetSummary(ctx, selection, filter)
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	c := summary.Coverage
	return &v0sv1.GetSummaryResponse{
		FindingCount: summary.FindingCount, UniqueVulnerabilityCount: summary.UniqueVulnerabilityCount,
		AffectedWorkloadCount: summary.AffectedWorkloadCount, SeverityCounts: severityCountsToProto(summary.SeverityCounts),
		UniqueKevVulnerabilityCount: summary.UniqueKEVVulnerabilityCount, KevAffectedWorkloadCount: summary.KEVAffectedWorkloadCount,
		Coverage: &v0sv1.WorkloadCoverage{
			TotalWorkloadCount: c.TotalWorkloadCount, ScannedCount: c.ScannedCount, PendingCount: c.PendingCount,
			NoSbomCount: c.NoSBOMCount, FailedCount: c.FailedCount, UnresolvedImageCount: c.UnresolvedImageCount,
		},
	}, nil
}
