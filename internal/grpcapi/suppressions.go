package grpcapi

import (
	"context"
	"strconv"
	"strings"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/database"
)

// SetSuppressions implements SuppressionService.
func (s *Server) SetSuppressions(ctx context.Context, req *v0sv1.SetSuppressionsRequest) (*v0sv1.SetSuppressionsResponse, error) {
	items := make([]database.NewSuppression, 0, len(req.GetSuppressions()))
	for _, n := range req.GetSuppressions() {
		items = append(items, database.NewSuppression{
			SuppressionKey: suppressionKey(n.GetKey()),
			State:          stateToDatabase(n.GetState()),
			Detail:         n.GetDetail(),
		})
	}
	set, err := s.db.SetSuppressions(ctx, req.GetTeam(), items, req.GetActor())
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	return &v0sv1.SetSuppressionsResponse{Suppressions: suppressionsToProto(set)}, nil
}

// DeleteSuppressions implements SuppressionService.
func (s *Server) DeleteSuppressions(ctx context.Context, req *v0sv1.DeleteSuppressionsRequest) (*v0sv1.DeleteSuppressionsResponse, error) {
	keys := make([]database.SuppressionKey, 0, len(req.GetKeys()))
	for _, k := range req.GetKeys() {
		keys = append(keys, suppressionKey(k))
	}
	deleted, err := s.db.DeleteSuppressions(ctx, req.GetTeam(), keys)
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	return &v0sv1.DeleteSuppressionsResponse{Deleted: suppressionsToProto(deleted)}, nil
}

// ListSuppressions implements SuppressionService.
func (s *Server) ListSuppressions(ctx context.Context, req *v0sv1.ListSuppressionsRequest) (*v0sv1.ListSuppressionsResponse, error) {
	if err := rejectLegacyTeams(req, 1); err != nil {
		return nil, err
	}
	if err := validateScope(req.GetTeam(), req.GetEnvironment(), req.GetWorkload()); err != nil {
		return nil, err
	}
	filter := database.SuppressionFilter{
		Teams:           teamFilter(req.GetTeam()),
		Environment:     req.GetEnvironment(),
		Workload:        req.GetWorkload(),
		ImageName:       req.GetImageName(),
		VulnerabilityID: req.GetVulnerabilityId(),
	}
	p, err := directedPage(req.GetPageSize(), req.GetPageToken(), req.GetPageDirection())
	if err != nil {
		return nil, err
	}
	list, err := s.db.ListSuppressions(ctx, filter, p)
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	resp := &v0sv1.ListSuppressionsResponse{
		Suppressions: suppressionsToProto(list.Suppressions), NextPageToken: list.NextPageToken,
		Cursors: list.Cursors, PageInfo: pageInfoToProto(list.PageInfo),
	}
	return resp, nil
}

func suppressionKey(k *v0sv1.SuppressionKey) database.SuppressionKey {
	return database.SuppressionKey{
		Environment: k.GetEnvironment(), Workload: k.GetWorkload(),
		ImageName: k.GetImageName(), Package: k.GetPackage(), VulnerabilityID: k.GetVulnerabilityId(),
	}
}

func suppressionsToProto(ss []database.Suppression) []*v0sv1.Suppression {
	out := make([]*v0sv1.Suppression, 0, len(ss))
	for _, s := range ss {
		out = append(out, suppressionToProto(s))
	}
	return out
}

func suppressionToProto(s database.Suppression) *v0sv1.Suppression {
	return &v0sv1.Suppression{
		Team:            s.Team,
		Environment:     s.Environment,
		Workload:        s.Workload,
		ImageName:       s.ImageName,
		PackageKey:      s.Package,
		VulnerabilityId: s.VulnerabilityID,
		State:           v0sv1.SuppressionState(v0sv1.SuppressionState_value["SUPPRESSION_STATE_"+strings.ToUpper(s.State)]),
		Detail:          s.Detail,
		UpdatedBy:       s.UpdatedBy,
		UpdatedAt:       timestamp(s.UpdatedAt),
	}
}

// stateToDatabase maps a suppression state to the database spelling, e.g.
// SUPPRESSION_STATE_NOT_AFFECTED to "not_affected". The zero value maps to
// "", and an unknown value to its number, which the database rejects.
func stateToDatabase(v v0sv1.SuppressionState) string {
	if v == v0sv1.SuppressionState_SUPPRESSION_STATE_UNSPECIFIED {
		return ""
	}
	name, ok := v0sv1.SuppressionState_name[int32(v)]
	if !ok {
		return strconv.Itoa(int(v))
	}
	return strings.ToLower(strings.TrimPrefix(name, "SUPPRESSION_STATE_"))
}
