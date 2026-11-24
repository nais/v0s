package grpcapi

import (
	"context"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/database"
)

func (s *Server) listWorkloadOverview(ctx context.Context, req *v0sv1.ListWorkloadsRequest, selection database.WorkloadFilter) (*v0sv1.ListWorkloadsResponse, error) {
	overview := req.GetOverview()
	f := overview.GetFindingFilter()
	if f.GetTeam() != "" || f.GetEnvironment() != "" || f.GetWorkload() != "" {
		return nil, invalidArgument("overview.finding_filter scope must be empty; use top-level team/environment/workload")
	}
	filter, err := findingFilter(f, nil)
	if err != nil {
		return nil, err
	}
	options := database.WorkloadOverviewOptions{FindingFilter: filter, AffectedOnly: overview.GetAffectedOnly()}
	if o := overview.GetOrderBy(); o != nil {
		switch o.GetField() {
		case v0sv1.WorkloadOrderBy_FIELD_WORKLOAD:
			options.Order.Field = database.WorkloadOrderIdentity
		case v0sv1.WorkloadOrderBy_FIELD_FINDING_COUNT:
			options.Order.Field = database.WorkloadOrderFindingCount
		default:
			return nil, invalidArgument("overview.order_by.field is required and must be valid")
		}
		switch o.GetDirection() {
		case v0sv1.WorkloadOrderBy_DIRECTION_ASC:
			options.Order.Direction = database.FindingOrderASC
		case v0sv1.WorkloadOrderBy_DIRECTION_DESC:
			options.Order.Direction = database.FindingOrderDESC
		default:
			return nil, invalidArgument("overview.order_by.direction is required and must be valid")
		}
	}
	list, err := s.db.ListWorkloadOverview(ctx, selection, page(req.GetPageSize(), req.GetPageToken()), options)
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	resp := &v0sv1.ListWorkloadsResponse{NextPageToken: list.NextPageToken, Cursors: list.Cursors, TotalCount: &list.TotalCount}
	for _, row := range list.Workloads {
		w := workloadToProto(row.Workload)
		c := row.Counts
		w.FindingCounts = &v0sv1.WorkloadFindingCounts{
			FindingCount: c.FindingCount, UniqueVulnerabilityCount: c.UniqueVulnerabilityCount,
			UniqueKevVulnerabilityCount: c.UniqueKEVVulnerabilityCount,
			SeverityCounts: &v0sv1.VulnerabilitySeverityCounts{
				Critical: c.SeverityCounts.Critical, High: c.SeverityCounts.High,
				Medium: c.SeverityCounts.Medium, Low: c.SeverityCounts.Low, Unknown: c.SeverityCounts.Unknown,
			},
		}
		resp.Workloads = append(resp.Workloads, w)
	}
	return resp, nil
}
