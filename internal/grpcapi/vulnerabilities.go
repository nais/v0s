package grpcapi

import (
	"context"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/database"
)

func (s *Server) ListVulnerabilities(ctx context.Context, req *v0sv1.ListVulnerabilitiesRequest) (*v0sv1.ListVulnerabilitiesResponse, error) {
	filter, err := findingFilter(req.GetFilter(), req.GetWorkloadSelector())
	if err != nil {
		return nil, err
	}
	var order database.VulnerabilityOrder
	if o := req.GetOrderBy(); o != nil {
		switch o.GetField() {
		case v0sv1.VulnerabilityOrderBy_FIELD_SEVERITY:
			order.Field = database.VulnerabilityOrderSeverity
		case v0sv1.VulnerabilityOrderBy_FIELD_VULNERABILITY_ID:
			order.Field = database.VulnerabilityOrderID
		case v0sv1.VulnerabilityOrderBy_FIELD_AFFECTED_WORKLOAD_COUNT:
			order.Field = database.VulnerabilityOrderWorkloads
		default:
			return nil, invalidArgument("order_by.field is required and must be valid")
		}
		switch o.GetDirection() {
		case v0sv1.VulnerabilityOrderBy_DIRECTION_ASC:
			order.Direction = database.FindingOrderASC
		case v0sv1.VulnerabilityOrderBy_DIRECTION_DESC:
			order.Direction = database.FindingOrderDESC
		default:
			return nil, invalidArgument("order_by.direction is required and must be valid")
		}
	}
	list, err := s.db.ListVulnerabilities(ctx, filter, page(req.GetPageSize(), req.GetPageToken()), order)
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	resp := &v0sv1.ListVulnerabilitiesResponse{NextPageToken: list.NextPageToken, Cursors: list.Cursors, TotalCount: list.TotalCount}
	for _, v := range list.Vulnerabilities {
		resp.Vulnerabilities = append(resp.Vulnerabilities, &v0sv1.VulnerabilitySummary{
			VulnerabilityId: v.VulnerabilityID, Severity: severityToProto(v.Severity),
			FindingCount: v.FindingCount, AffectedWorkloadCount: v.AffectedWorkloadCount,
		})
	}
	return resp, nil
}
