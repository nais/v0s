// Package grpcapi serves the v0s.v1 gRPC API from the database.
package grpcapi

import (
	"context"
	"errors"
	"log/slog"
	"runtime/debug"
	"strings"
	"time"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/v0s"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Server implements VulnerabilityService and SuppressionService.
type Server struct {
	v0sv1.UnimplementedVulnerabilityServiceServer
	v0sv1.UnimplementedSuppressionServiceServer

	db  *database.DB
	log *slog.Logger
}

// New returns a Server reading from and writing to db.
func New(db *database.DB, log *slog.Logger) *Server {
	return &Server{db: db, log: log}
}

// Register registers both services on r.
func (s *Server) Register(r grpc.ServiceRegistrar) {
	v0sv1.RegisterVulnerabilityServiceServer(r, s)
	v0sv1.RegisterSuppressionServiceServer(r, s)
}

// toStatus maps a database error to a gRPC status. Unexpected errors are
// logged and returned as Internal without details.
func (s *Server) toStatus(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, database.ErrInvalid):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, database.ErrNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, database.ErrUnavailable):
		return status.Error(codes.Unavailable, "CISA KEV catalog is not available")
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "deadline exceeded")
	}
	method, _ := grpc.Method(ctx)
	s.log.With("method", method, "err", err).Error("request failed")
	return status.Error(codes.Internal, "internal error")
}

// RecoveryInterceptor returns an interceptor that turns a panic in a later
// interceptor or handler into an Internal error instead of a crashed process.
func RecoveryInterceptor(log *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if p := recover(); p != nil {
				log.With("method", info.FullMethod, "panic", p, "stack", string(debug.Stack())).Error("request panicked")
				resp, err = nil, status.Error(codes.Internal, "internal error")
			}
		}()
		return handler(ctx, req)
	}
}

func invalidArgument(format string, args ...any) error {
	return status.Errorf(codes.InvalidArgument, format, args...)
}

func page(size int32, token string) database.Page {
	return database.Page{Size: int(size), Token: token}
}

// ListWorkloads implements VulnerabilityService.
func (s *Server) ListWorkloads(ctx context.Context, req *v0sv1.ListWorkloadsRequest) (*v0sv1.ListWorkloadsResponse, error) {
	if err := rejectLegacyTeams(req, 1); err != nil {
		return nil, err
	}
	if err := validateScope(req.GetTeam(), req.GetEnvironment(), req.GetWorkload()); err != nil {
		return nil, err
	}
	filter := database.WorkloadFilter{Teams: teamFilter(req.GetTeam()), Environment: req.GetEnvironment(), Workload: req.GetWorkload()}
	workloads, next, err := s.db.ListWorkloads(ctx, filter, page(req.GetPageSize(), req.GetPageToken()))
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	resp := &v0sv1.ListWorkloadsResponse{Workloads: make([]*v0sv1.Workload, 0, len(workloads)), NextPageToken: next}
	for _, w := range workloads {
		pw := &v0sv1.Workload{Environment: w.Environment, Team: w.Team, Name: w.Name, ImageReference: w.ImageReference, ResolveError: w.ResolveError}
		if w.Image != nil {
			pw.Image = imageToProto(*w.Image)
		}
		resp.Workloads = append(resp.Workloads, pw)
	}
	return resp, nil
}

// ListFindings implements VulnerabilityService.
func (s *Server) ListFindings(ctx context.Context, req *v0sv1.ListFindingsRequest) (*v0sv1.ListFindingsResponse, error) {
	filter, err := findingFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	findings, next, err := s.db.ListFindings(ctx, filter, page(req.GetPageSize(), req.GetPageToken()))
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	resp := &v0sv1.ListFindingsResponse{
		Findings: make([]*v0sv1.Finding, 0, len(findings)), NextPageToken: next,
		Cursors: make([]string, 0, len(findings)),
	}
	for _, f := range findings {
		cursor, err := f.PageToken()
		if err != nil {
			return nil, s.toStatus(ctx, err)
		}
		pf := &v0sv1.Finding{
			Workload:         &v0sv1.WorkloadRef{Environment: f.Workload.Environment, Team: f.Workload.Team, Name: f.Workload.Name},
			Image:            imageToProto(f.Image),
			VulnerabilityId:  f.Finding.VulnerabilityID,
			Purl:             f.Finding.PURL,
			PackageKey:       f.Finding.PackageKey,
			InstalledVersion: f.Finding.InstalledVersion,
			FixedVersion:     f.Finding.FixedVersion,
			Severity:         severityToProto(f.Finding.Severity),
			SeveritySource:   f.Finding.SeveritySource,
			DataSource:       f.Finding.DataSource,
			Epss:             epssToProto(f.EPSS),
			KnownExploited:   f.KnownExploited,
		}
		if f.Suppression != nil {
			pf.Suppression = suppressionToProto(*f.Suppression)
		}
		resp.Findings = append(resp.Findings, pf)
		resp.Cursors = append(resp.Cursors, cursor)
	}
	return resp, nil
}

// CountFindings implements VulnerabilityService.
func (s *Server) CountFindings(ctx context.Context, req *v0sv1.CountFindingsRequest) (*v0sv1.CountFindingsResponse, error) {
	var groupBy database.GroupBy
	switch req.GetGroupBy() {
	case v0sv1.CountFindingsRequest_GROUP_BY_SEVERITY:
		groupBy = database.GroupBySeverity
	case v0sv1.CountFindingsRequest_GROUP_BY_TEAM:
		groupBy = database.GroupByTeam
	case v0sv1.CountFindingsRequest_GROUP_BY_WORKLOAD:
		groupBy = database.GroupByWorkload
	case v0sv1.CountFindingsRequest_GROUP_BY_IMAGE:
		groupBy = database.GroupByImage
	case v0sv1.CountFindingsRequest_GROUP_BY_VULNERABILITY:
		groupBy = database.GroupByVulnerability
	default:
		return nil, invalidArgument("group_by is required")
	}
	filter, err := findingFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	counts, err := s.db.CountFindings(ctx, filter, groupBy)
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	resp := &v0sv1.CountFindingsResponse{Buckets: make([]*v0sv1.CountFindingsResponse_Bucket, 0, len(counts))}
	for _, c := range counts {
		resp.Buckets = append(resp.Buckets, &v0sv1.CountFindingsResponse_Bucket{Key: c.Key, Count: c.Count})
	}
	return resp, nil
}

// GetVulnerability implements VulnerabilityService.
func (s *Server) GetVulnerability(ctx context.Context, req *v0sv1.GetVulnerabilityRequest) (*v0sv1.GetVulnerabilityResponse, error) {
	if req.GetId() == "" {
		return nil, invalidArgument("id is required")
	}
	v, err := s.db.GetVulnerability(ctx, req.GetId())
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	pv := &v0sv1.Vulnerability{
		Id:             v.ID,
		Aliases:        v.Aliases,
		Title:          v.Title,
		Description:    v.Description,
		Cvss:           cvssToProto(v.CVSS),
		References:     v.References,
		Epss:           epssToProto(v.EPSS),
		KnownExploited: v.KnownExploited,
	}
	return &v0sv1.GetVulnerabilityResponse{Vulnerability: pv}, nil
}

// SearchComponents implements VulnerabilityService.
func (s *Server) SearchComponents(ctx context.Context, req *v0sv1.SearchComponentsRequest) (*v0sv1.SearchComponentsResponse, error) {
	if err := rejectLegacyTeams(req, 2); err != nil {
		return nil, err
	}
	filter := database.ComponentFilter{Query: req.GetQuery(), Teams: teamFilter(req.GetTeam())}
	matches, next, err := s.db.SearchComponents(ctx, filter, page(req.GetPageSize(), req.GetPageToken()))
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	resp := &v0sv1.SearchComponentsResponse{Matches: make([]*v0sv1.ComponentMatch, 0, len(matches)), NextPageToken: next}
	for _, m := range matches {
		pm := &v0sv1.ComponentMatch{
			Purl:      m.Component.PURL,
			Name:      m.Component.Name,
			Version:   m.Component.Version,
			Image:     imageToProto(m.Image),
			Workloads: workloadRefsToProto(m.Workloads),
		}
		resp.Matches = append(resp.Matches, pm)
	}
	return resp, nil
}

func workloadRefsToProto(ws []database.WorkloadRef) []*v0sv1.WorkloadRef {
	out := make([]*v0sv1.WorkloadRef, 0, len(ws))
	for _, w := range ws {
		out = append(out, &v0sv1.WorkloadRef{Environment: w.Environment, Team: w.Team, Name: w.Name})
	}
	return out
}

func findingFilter(f *v0sv1.FindingFilter) (database.FindingFilter, error) {
	if err := rejectLegacyTeams(f, 1); err != nil {
		return database.FindingFilter{}, err
	}
	if err := validateScope(f.GetTeam(), f.GetEnvironment(), f.GetWorkload()); err != nil {
		return database.FindingFilter{}, err
	}
	for _, id := range f.GetVulnerabilityIds() {
		if strings.TrimSpace(id) == "" {
			return database.FindingFilter{}, invalidArgument("vulnerability_ids cannot contain empty values")
		}
	}
	filter := database.FindingFilter{
		Teams:              teamFilter(f.GetTeam()),
		Environment:        f.GetEnvironment(),
		Workload:           f.GetWorkload(),
		ImageName:          f.GetImageName(),
		ImageDigest:        f.GetImageDigest(),
		VulnerabilityID:    f.GetVulnerabilityId(),
		VulnerabilityIDs:   f.GetVulnerabilityIds(),
		Package:            f.GetPackage(),
		HasFix:             f.GetHasFix(),
		OnlyKnownExploited: f.GetOnlyKnownExploited(),
	}
	for _, sev := range f.GetSeverities() {
		name, ok := v0sv1.Severity_name[int32(sev)]
		if !ok || sev == v0sv1.Severity_SEVERITY_UNSPECIFIED {
			return database.FindingFilter{}, invalidArgument("invalid severity %d", sev)
		}
		filter.Severities = append(filter.Severities, v0s.Severity(strings.TrimPrefix(name, "SEVERITY_")))
	}
	switch f.GetSuppressed() {
	case v0sv1.SuppressedFilter_SUPPRESSED_FILTER_UNSPECIFIED, v0sv1.SuppressedFilter_SUPPRESSED_FILTER_EXCLUDE:
		filter.Suppressed = database.SuppressedExclude
	case v0sv1.SuppressedFilter_SUPPRESSED_FILTER_INCLUDE:
		filter.Suppressed = database.SuppressedInclude
	case v0sv1.SuppressedFilter_SUPPRESSED_FILTER_ONLY:
		filter.Suppressed = database.SuppressedOnly
	default:
		return database.FindingFilter{}, invalidArgument("invalid suppressed filter %d", f.GetSuppressed())
	}
	return filter, nil
}

func imageToProto(img v0s.Image) *v0sv1.Image {
	return &v0sv1.Image{
		Name:      img.Name,
		Digest:    img.Digest,
		Status:    v0sv1.ImageStatus(v0sv1.ImageStatus_value["IMAGE_STATUS_"+strings.ToUpper(string(img.Status()))]),
		Error:     img.Error,
		ScannedAt: timestamp(img.ScannedAt),
	}
}

func severityToProto(s v0s.Severity) v0sv1.Severity {
	return v0sv1.Severity(v0sv1.Severity_value["SEVERITY_"+string(s)])
}

func epssToProto(e *v0s.EPSS) *v0sv1.Epss {
	if e == nil {
		return nil
	}
	return &v0sv1.Epss{Score: e.Score, Date: date(e.Date)}
}

// timestamp returns nil for the zero time.
func timestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// date formats t as YYYY-MM-DD, or "" for the zero time.
func date(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.DateOnly)
}
