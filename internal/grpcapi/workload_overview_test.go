package grpcapi_test

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/grpcapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func newWorkloadOverviewServer(t *testing.T) *grpcapi.Server {
	t.Helper()
	return newServer(t, `
		UPDATE images SET sbom_state = 'fetched', sbom = '', scanned_at = '2026-01-02';
		INSERT INTO vulnerabilities (id, db_version) VALUES ('CVE-2', now());
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, fixed_version, status, severity)
		SELECT id, 'CVE-1', 'pkg:npm/other@1', 'pkg:npm/other', '1', '2', 'affected', 'LOW' FROM images;
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, status, severity)
		SELECT id, 'CVE-2', 'pkg:maven/example/lib@1', 'pkg:maven/example/lib', '1', 'affected', 'UNKNOWN' FROM images;
		INSERT INTO images (name, digest, sbom_state, sbom, scanned_at, error) VALUES
			('repo/clean', 'clean', 'fetched', '', '2026-01-02', ''),
			('repo/failed', 'failed', 'failed', NULL, NULL, 'fetch failed'),
			('repo/missing', 'missing', 'missing', NULL, NULL, 'no attestation'),
			('repo/pending', 'pending', 'pending', NULL, NULL, '');
		INSERT INTO workloads (environment, team, name, image_reference, image_id)
		SELECT 'dev', 'team', substring(name from 6), name || ':1', id FROM images WHERE name <> 'repo/app';
		INSERT INTO workloads (environment, team, name, image_reference, resolve_error)
		VALUES ('dev', 'team', 'unresolved', 'repo/unresolved:latest', 'tag not found');
		INSERT INTO suppressions (team, environment, workload, image_name, package_key, vulnerability_id, state, detail, updated_by)
		VALUES ('team', 'dev', 'app', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'assessed', 'user');
	`)
}

func TestWorkloadOverviewContract(t *testing.T) {
	s := newWorkloadOverviewServer(t)
	tests := []struct {
		order *v0sv1.WorkloadOrderBy
		want  []string
	}{
		{nil, []string{"dev/app", "dev/clean", "dev/failed", "dev/missing", "dev/pending", "dev/unresolved", "dev/worker", "prod/app", "prod/worker"}},
		{&v0sv1.WorkloadOrderBy{Field: v0sv1.WorkloadOrderBy_FIELD_FINDING_COUNT, Direction: v0sv1.WorkloadOrderBy_DIRECTION_ASC},
			[]string{"dev/clean", "dev/failed", "dev/missing", "dev/pending", "dev/unresolved", "dev/app", "dev/worker", "prod/app", "prod/worker"}},
		{&v0sv1.WorkloadOrderBy{Field: v0sv1.WorkloadOrderBy_FIELD_FINDING_COUNT, Direction: v0sv1.WorkloadOrderBy_DIRECTION_DESC},
			[]string{"dev/worker", "prod/app", "prod/worker", "dev/app", "dev/clean", "dev/failed", "dev/missing", "dev/pending", "dev/unresolved"}},
	}
	for _, tt := range tests {
		for _, size := range []int32{1, 2} {
			req := &v0sv1.ListWorkloadsRequest{Team: "team", PageSize: size, Overview: &v0sv1.WorkloadOverviewOptions{OrderBy: tt.order}}
			wire, err := proto.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			decoded := new(v0sv1.ListWorkloadsRequest)
			if err := proto.Unmarshal(wire, decoded); err != nil {
				t.Fatal(err)
			}
			var got []string
			for range 10 {
				resp, err := s.ListWorkloads(t.Context(), decoded)
				if err != nil {
					t.Fatal(err)
				}
				if resp.TotalCount == nil || resp.GetTotalCount() != 9 || len(resp.GetCursors()) != len(resp.GetWorkloads()) {
					t.Fatalf("page metadata: %v", resp)
				}
				for _, w := range resp.GetWorkloads() {
					got = append(got, w.GetEnvironment()+"/"+w.GetName())
					c := w.GetFindingCounts()
					if c == nil || c.GetSeverityCounts() == nil {
						t.Fatalf("missing counts: %v", w)
					}
					counts := c.GetSeverityCounts()
					if counts.GetCritical()+counts.GetHigh()+counts.GetMedium()+counts.GetLow()+counts.GetUnknown() != c.GetUniqueVulnerabilityCount() {
						t.Fatalf("severity sum: %v", w)
					}
					if w.GetName() == "app" || w.GetName() == "worker" {
						wantFindings := int64(3)
						if w.GetEnvironment() == "dev" && w.GetName() == "app" {
							wantFindings = 2
							if counts.GetLow() != 1 {
								t.Fatalf("assessment did not affect severity: %v", w)
							}
						} else if counts.GetHigh() != 1 {
							t.Fatalf("highest matching severity: %v", w)
						}
						if c.GetFindingCount() != wantFindings || c.GetUniqueVulnerabilityCount() != 2 || c.GetUniqueKevVulnerabilityCount() != 1 || counts.GetUnknown() != 1 {
							t.Fatalf("incorrect counts: %v", w)
						}
					} else if c.GetFindingCount() != 0 || c.GetUniqueVulnerabilityCount() != 0 || c.GetUniqueKevVulnerabilityCount() != 0 {
						t.Fatalf("zero finding workload: %v", w)
					}
					switch w.GetName() {
					case "clean":
						if w.GetImage().GetStatus() != v0sv1.ImageStatus_IMAGE_STATUS_SCANNED {
							t.Fatal(w)
						}
					case "failed":
						if w.GetImage().GetStatus() != v0sv1.ImageStatus_IMAGE_STATUS_FAILED || w.GetImage().GetError() != "fetch failed" {
							t.Fatal(w)
						}
					case "missing":
						if w.GetImage().GetStatus() != v0sv1.ImageStatus_IMAGE_STATUS_NO_SBOM {
							t.Fatal(w)
						}
					case "pending":
						if w.GetImage().GetStatus() != v0sv1.ImageStatus_IMAGE_STATUS_PENDING {
							t.Fatal(w)
						}
					case "unresolved":
						if w.GetImage() != nil || w.GetResolveError() != "tag not found" {
							t.Fatal(w)
						}
					}
				}
				decoded.PageToken = resp.GetCursors()[len(resp.GetCursors())-1]
				if resp.GetNextPageToken() == "" {
					empty, err := s.ListWorkloads(t.Context(), decoded)
					if err != nil || empty.TotalCount == nil || empty.GetTotalCount() != 9 || len(empty.GetWorkloads()) != 0 || empty.GetNextPageToken() != "" || len(empty.GetCursors()) != 0 {
						t.Fatalf("empty continuation: %v, %v", empty, err)
					}
					break
				}
				if resp.GetNextPageToken() != decoded.PageToken {
					t.Fatal("next token differs from last row cursor")
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("order %v size %d: %v, want %v", tt.order, size, got, tt.want)
			}
		}
	}
}

func TestWorkloadOverviewSelectionAndFilters(t *testing.T) {
	s := newWorkloadOverviewServer(t)
	for _, tt := range []struct {
		filter   *v0sv1.FindingFilter
		affected bool
		total    int64
	}{
		{total: 9},
		{affected: true, total: 4},
		{filter: &v0sv1.FindingFilter{PackageType: "maven"}, total: 9},
		{filter: &v0sv1.FindingFilter{PackageType: "missing"}, total: 9},
		{filter: &v0sv1.FindingFilter{PackageType: "missing"}, affected: true},
		{filter: &v0sv1.FindingFilter{OnlyKnownExploited: true}, affected: true, total: 4},
		{filter: &v0sv1.FindingFilter{HasFix: true}, total: 9},
		{filter: &v0sv1.FindingFilter{Suppressed: v0sv1.SuppressedFilter_SUPPRESSED_FILTER_ONLY}, affected: true, total: 1},
	} {
		resp, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{Overview: &v0sv1.WorkloadOverviewOptions{FindingFilter: tt.filter, AffectedOnly: tt.affected}})
		if err != nil || resp.GetTotalCount() != tt.total || int64(len(resp.GetWorkloads())) != tt.total {
			t.Fatalf("filter %v affected %v: %v, %v", tt.filter, tt.affected, resp, err)
		}
		if tt.filter != nil && tt.filter.PackageType == "missing" {
			for _, w := range resp.GetWorkloads() {
				if w.GetFindingCounts().GetFindingCount() != 0 {
					t.Fatalf("finding filter not applied: %v", w)
				}
			}
		}
	}
	one, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{Team: "team", Environment: "dev", Workload: "app", Overview: &v0sv1.WorkloadOverviewOptions{}})
	if err != nil || one.GetTotalCount() != 1 || len(one.GetWorkloads()) != 1 {
		t.Fatalf("existing scope selection: %v, %v", one, err)
	}
}

func TestWorkloadOverviewErrorsAndLegacy(t *testing.T) {
	s := newWorkloadOverviewServer(t)
	for _, f := range []*v0sv1.FindingFilter{
		{Team: "team"}, {Environment: "dev"}, {Workload: "app"},
		{Package: "invalid"}, {PackageType: "npm/no"}, {Severities: []v0sv1.Severity{0}}, {Suppressed: 99},
	} {
		if _, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{Overview: &v0sv1.WorkloadOverviewOptions{FindingFilter: f}}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("invalid overview filter %v: %v", f, err)
		}
	}
	if _, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{Workload: "app", Overview: &v0sv1.WorkloadOverviewOptions{}}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("incomplete scope: %v", err)
	}
	for _, order := range []*v0sv1.WorkloadOrderBy{
		{}, {Field: v0sv1.WorkloadOrderBy_FIELD_FINDING_COUNT},
		{Direction: v0sv1.WorkloadOrderBy_DIRECTION_ASC},
		{Field: 99, Direction: v0sv1.WorkloadOrderBy_DIRECTION_ASC},
		{Field: v0sv1.WorkloadOrderBy_FIELD_FINDING_COUNT, Direction: 99},
		{Field: v0sv1.WorkloadOrderBy_FIELD_WORKLOAD, Direction: v0sv1.WorkloadOrderBy_DIRECTION_DESC},
	} {
		if _, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{Overview: &v0sv1.WorkloadOverviewOptions{OrderBy: order}}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("invalid order %v: %v", order, err)
		}
	}
	first, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{PageSize: 1, Overview: &v0sv1.WorkloadOverviewOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []*v0sv1.ListWorkloadsRequest{
		{PageToken: first.GetNextPageToken()},
		{Team: "other", PageToken: first.GetNextPageToken(), Overview: &v0sv1.WorkloadOverviewOptions{}},
		{PageToken: first.GetNextPageToken(), Overview: &v0sv1.WorkloadOverviewOptions{AffectedOnly: true}},
		{PageToken: first.GetNextPageToken(), Overview: &v0sv1.WorkloadOverviewOptions{OrderBy: &v0sv1.WorkloadOrderBy{Field: v0sv1.WorkloadOrderBy_FIELD_FINDING_COUNT, Direction: v0sv1.WorkloadOrderBy_DIRECTION_DESC}}},
	} {
		if _, err := s.ListWorkloads(t.Context(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("incompatible cursor parameters: %v", err)
		}
	}
	legacy, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{PageSize: 1})
	wantLegacyToken := base64.RawURLEncoding.EncodeToString([]byte(`{"e":"dev","t":"team","w":"app"}`))
	if err != nil || legacy.GetNextPageToken() != wantLegacyToken || legacy.TotalCount != nil || len(legacy.GetCursors()) != 0 || legacy.GetWorkloads()[0].GetFindingCounts() != nil {
		t.Fatalf("legacy response changed: %v, %v", legacy, err)
	}
	if _, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{PageToken: wantLegacyToken}); err != nil {
		t.Fatalf("legacy continuation: %v", err)
	}
	for _, token := range []string{wantLegacyToken, "garbage!", base64.RawURLEncoding.EncodeToString([]byte(`{"version":99}`))} {
		if _, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{PageToken: token, Overview: &v0sv1.WorkloadOverviewOptions{}}); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "restart pagination") {
			t.Errorf("invalid cursor %q: %v", token, err)
		}
	}
	noKEV := newServer(t, `DELETE FROM kev`)
	if _, err := noKEV.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{}); err != nil {
		t.Errorf("legacy acquired KEV dependency: %v", err)
	}
	if resp, err := noKEV.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{Overview: &v0sv1.WorkloadOverviewOptions{}}); status.Code(err) != codes.Unavailable || resp != nil {
		t.Errorf("missing KEV catalog returned misleading counts: %v, %v", resp, err)
	}
}
