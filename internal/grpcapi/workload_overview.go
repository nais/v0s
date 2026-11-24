package grpcapi

import (
	"context"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/database"
)

func (s *Server) listWorkloadOverview(ctx context.Context, req *v0sv1.ListWorkloadsRequest, selection database.WorkloadFilter) (*v0sv1.ListWorkloadsResponse, error) {
	overview := req.GetOverview()
	filter, err := unscopedFindingFilter(overview.GetFindingFilter(), "overview.finding_filter")
	if err != nil {
		return nil, err
	}
	list, err := s.db.ListWorkloadOverview(ctx, selection, page(req.GetPageSize(), req.GetPageToken()), filter)
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	resp := &v0sv1.ListWorkloadsResponse{NextPageToken: list.NextPageToken, TotalCount: &list.TotalCount}
	for _, row := range list.Workloads {
		w := workloadToProto(row.Workload)
		c := row.Counts
		w.FindingCounts = &v0sv1.WorkloadFindingCounts{
			FindingCount: c.FindingCount, UniqueVulnerabilityCount: c.UniqueVulnerabilityCount,
			UniqueKevVulnerabilityCount: c.UniqueKEVVulnerabilityCount,
			SeverityCounts:              severityCountsToProto(c.SeverityCounts),
		}
		resp.Workloads = append(resp.Workloads, w)
	}
	return resp, nil
}
