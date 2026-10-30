package grpcapi

import (
	"context"
	"strconv"
	"strings"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/database"
)

// CreateSuppressions implements SuppressionService.
func (s *Server) CreateSuppressions(ctx context.Context, req *v0sv1.CreateSuppressionsRequest) (*v0sv1.CreateSuppressionsResponse, error) {
	if len(req.GetSuppressions()) == 0 {
		return nil, invalidArgument("no suppressions")
	}
	items := make([]database.NewSuppression, 0, len(req.GetSuppressions()))
	for _, n := range req.GetSuppressions() {
		item := database.NewSuppression{
			ImageName:       n.GetImageName(),
			Package:         n.GetPackage(),
			VulnerabilityID: n.GetVulnerabilityId(),
			State:           enumToDatabase(v0sv1.SuppressionState_name, int32(n.GetState()), "SUPPRESSION_STATE_"),
			Justification:   enumToDatabase(v0sv1.Justification_name, int32(n.GetJustification()), "JUSTIFICATION_"),
			Detail:          n.GetDetail(),
		}
		if n.GetExpiresAt() != nil {
			item.ExpiresAt = n.GetExpiresAt().AsTime()
		}
		items = append(items, item)
	}
	created, err := s.db.CreateSuppressions(ctx, items, req.GetActor(), req.GetDryRun())
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	resp := &v0sv1.CreateSuppressionsResponse{Results: make([]*v0sv1.CreateSuppressionsResponse_CreatedSuppression, 0, len(created))}
	for _, c := range created {
		resp.Results = append(resp.Results, &v0sv1.CreateSuppressionsResponse_CreatedSuppression{
			Suppression:     suppressionToProto(c.Suppression),
			MatchedFindings: c.MatchedFindings,
			ReplacesId:      c.ReplacesID,
		})
	}
	return resp, nil
}

// RevokeSuppressions implements SuppressionService.
func (s *Server) RevokeSuppressions(ctx context.Context, req *v0sv1.RevokeSuppressionsRequest) (*v0sv1.RevokeSuppressionsResponse, error) {
	revoked, err := s.db.RevokeSuppressions(ctx, req.GetIds(), req.GetActor(), req.GetReason())
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	resp := &v0sv1.RevokeSuppressionsResponse{Revoked: make([]*v0sv1.Suppression, 0, len(revoked))}
	for _, r := range revoked {
		resp.Revoked = append(resp.Revoked, suppressionToProto(r))
	}
	return resp, nil
}

// ListSuppressions implements SuppressionService.
func (s *Server) ListSuppressions(ctx context.Context, req *v0sv1.ListSuppressionsRequest) (*v0sv1.ListSuppressionsResponse, error) {
	filter := database.SuppressionFilter{
		ImageName:       req.GetImageName(),
		VulnerabilityID: req.GetVulnerabilityId(),
		IncludeInactive: req.GetIncludeInactive(),
	}
	suppressions, next, err := s.db.ListSuppressions(ctx, filter, page(req.GetPageSize(), req.GetPageToken()))
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	resp := &v0sv1.ListSuppressionsResponse{Suppressions: make([]*v0sv1.Suppression, 0, len(suppressions)), NextPageToken: next}
	for _, sup := range suppressions {
		resp.Suppressions = append(resp.Suppressions, suppressionToProto(sup))
	}
	return resp, nil
}

func suppressionToProto(s database.Suppression) *v0sv1.Suppression {
	return &v0sv1.Suppression{
		Id:              s.ID,
		ImageName:       s.ImageName,
		PackageKey:      s.PackageKey,
		VulnerabilityId: s.VulnerabilityID,
		State:           v0sv1.SuppressionState(v0sv1.SuppressionState_value["SUPPRESSION_STATE_"+strings.ToUpper(s.State)]),
		Justification:   v0sv1.Justification(v0sv1.Justification_value["JUSTIFICATION_"+strings.ToUpper(s.Justification)]),
		Detail:          s.Detail,
		CreatedBy:       s.CreatedBy,
		CreatedAt:       timestamp(s.CreatedAt),
		ExpiresAt:       timestamp(s.ExpiresAt),
		RevokedAt:       timestamp(s.RevokedAt),
		RevokedBy:       s.RevokedBy,
		RevokeReason:    s.RevokeReason,
	}
}

// enumToDatabase maps a proto enum value to the database spelling, e.g.
// SUPPRESSION_STATE_NOT_AFFECTED to "not_affected". The zero value maps to
// "", and an unknown value to its number, which the database rejects.
func enumToDatabase(names map[int32]string, v int32, prefix string) string {
	if v == 0 {
		return ""
	}
	name, ok := names[v]
	if !ok {
		return strconv.Itoa(int(v))
	}
	return strings.ToLower(strings.TrimPrefix(name, prefix))
}
