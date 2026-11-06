// Package grpcapi serves the v0s.v1 gRPC API from the database.
package grpcapi

import (
	"context"
	"errors"
	"log/slog"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"github.com/nais/v0s"
	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/database"
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
	filter := database.WorkloadFilter{Teams: req.GetTeams(), Environment: req.GetEnvironment()}
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
	resp := &v0sv1.ListFindingsResponse{Findings: make([]*v0sv1.Finding, 0, len(findings)), NextPageToken: next}
	for _, f := range findings {
		pf := &v0sv1.Finding{
			Workload:         &v0sv1.WorkloadRef{Environment: f.Workload.Environment, Team: f.Workload.Team, Name: f.Workload.Name},
			Image:            imageToProto(f.Image),
			VulnerabilityId:  f.Finding.VulnerabilityID,
			Purl:             f.Finding.PURL,
			PackageKey:       f.Finding.PackageKey,
			InstalledVersion: f.Finding.InstalledVersion,
			FixedVersion:     f.Finding.FixedVersion,
			Status:           f.Finding.Status,
			Severity:         severityToProto(f.Finding.Severity),
			SeveritySource:   f.Finding.SeveritySource,
			DataSource:       f.Finding.DataSource,
			Title:            f.Title,
			CvssScore:        f.CVSSScore,
			Epss:             epssToProto(f.EPSS),
			Kev:              kevToProto(f.KEV),
		}
		if f.Suppression != nil {
			pf.Suppression = suppressionToProto(*f.Suppression)
		}
		resp.Findings = append(resp.Findings, pf)
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
		Id:          v.ID,
		Aliases:     v.Aliases,
		Title:       v.Title,
		Description: v.Description,
		Severities:  make(map[string]v0sv1.Severity, len(v.Severities)),
		References:  v.References,
		PublishedAt: timestamp(v.PublishedAt),
		ModifiedAt:  timestamp(v.ModifiedAt),
		Epss:        epssToProto(v.EPSS),
		Kev:         kevToProto(v.KEV),
	}
	for source, sev := range v.Severities {
		pv.Severities[source] = severityToProto(sev)
	}
	for source, c := range v.CVSS {
		pv.Cvss = append(pv.Cvss, &v0sv1.Cvss{Source: source, V3Vector: c.V3Vector, V3Score: c.V3Score, V40Vector: c.V40Vector, V40Score: c.V40Score})
	}
	// Map iteration order is random; keep the response stable.
	slices.SortFunc(pv.Cvss, func(a, b *v0sv1.Cvss) int { return strings.Compare(a.Source, b.Source) })
	return &v0sv1.GetVulnerabilityResponse{Vulnerability: pv}, nil
}

// SearchComponents implements VulnerabilityService.
func (s *Server) SearchComponents(ctx context.Context, req *v0sv1.SearchComponentsRequest) (*v0sv1.SearchComponentsResponse, error) {
	filter := database.ComponentFilter{Query: req.GetQuery(), Teams: req.GetTeams()}
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
	filter := database.FindingFilter{
		Teams:           f.GetTeams(),
		Environment:     f.GetEnvironment(),
		Workload:        f.GetWorkload(),
		ImageName:       f.GetImageName(),
		ImageDigest:     f.GetImageDigest(),
		VulnerabilityID: f.GetVulnerabilityId(),
		Package:         f.GetPackage(),
		HasFix:          f.GetHasFix(),
		KEV:             f.GetKev(),
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
		Name:             img.Name,
		Digest:           img.Digest,
		Status:           v0sv1.ImageStatus(v0sv1.ImageStatus_value["IMAGE_STATUS_"+strings.ToUpper(string(img.Status()))]),
		Error:            img.Error,
		ScannedAt:        timestamp(img.ScannedAt),
		ScannedDbVersion: timestamp(img.ScannedDBVersion),
	}
}

func severityToProto(s v0s.Severity) v0sv1.Severity {
	return v0sv1.Severity(v0sv1.Severity_value["SEVERITY_"+string(s)])
}

func epssToProto(e *v0s.EPSS) *v0sv1.Epss {
	if e == nil {
		return nil
	}
	return &v0sv1.Epss{Score: e.Score, Percentile: e.Percentile, Date: date(e.Date)}
}

func kevToProto(k *v0s.KEV) *v0sv1.Kev {
	if k == nil {
		return nil
	}
	return &v0sv1.Kev{DateAdded: date(k.DateAdded), DueDate: date(k.DueDate), KnownRansomwareCampaign: k.KnownRansomwareCampaign}
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
