package grpcapi_test

import (
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/grpcapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

func workloadSelectorClient(t *testing.T) v0sv1.VulnerabilityServiceClient {
	t.Helper()
	s := newServer(t, `
		INSERT INTO vulnerabilities (id, db_version) VALUES ('CVE-2', now()), ('CVE-3', now());
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, status, severity)
		SELECT id, 'CVE-2', 'pkg:maven/example/lib@1', 'pkg:maven/example/lib', '1', 'affected', 'UNKNOWN' FROM images;
		INSERT INTO workloads (environment, team, name, image_reference, image_id)
		SELECT 'stage', 'other', 'app', 'repo/app:1', id FROM images;
		INSERT INTO images (name, digest, sbom_state, sbom, scanned_at) VALUES
			('repo/other', 'other', 'pending', NULL, NULL),
			('repo/clean', 'clean', 'fetched', '', '2026-01-02');
		INSERT INTO workloads (environment, team, name, image_reference, image_id)
		SELECT 'prod', 'other', 'app', 'repo/other:1', id FROM images WHERE name='repo/other';
		INSERT INTO workloads (environment, team, name, image_reference, image_id)
		SELECT 'dev', 'team', 'clean', 'repo/clean:1', id FROM images WHERE name='repo/clean';
		INSERT INTO workloads (environment, team, name, image_reference, resolve_error)
		VALUES ('dev', 'team', 'unresolved', 'repo/unresolved:1', 'tag not found');
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, status, severity)
		SELECT id, 'CVE-3', 'pkg:npm/other@1', 'pkg:npm/other', '1', 'affected', 'UNKNOWN' FROM images WHERE name='repo/other';
		INSERT INTO suppressions (team, environment, workload, image_name, package_key, vulnerability_id, state, detail, updated_by)
		VALUES ('team', 'dev', 'app', 'repo/app', 'pkg:npm/lodash', 'CVE-1', 'accepted_risk', 'assessed', 'user');
	`)
	return serveVulnerabilities(t, s)
}

func serveVulnerabilities(t *testing.T, s *grpcapi.Server) v0sv1.VulnerabilityServiceClient {
	t.Helper()
	srv := grpc.NewServer()
	s.Register(srv)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(listener) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return v0sv1.NewVulnerabilityServiceClient(conn)
}

func apiWorkloadSelector() *v0sv1.WorkloadSelector {
	return &v0sv1.WorkloadSelector{Workloads: []*v0sv1.WorkloadRef{
		{Environment: "dev", Team: "team", Name: "app"},
		{Environment: "prod", Team: "team", Name: "worker"},
		{Environment: "stage", Team: "other", Name: "app"},
		{Environment: "dev", Team: "team", Name: "clean"},
		{Environment: "dev", Team: "team", Name: "unresolved"},
	}}
}

func TestWorkloadSelectorOverGRPC(t *testing.T) {
	client := workloadSelectorClient(t)
	for _, tt := range []struct {
		name                string
		selector            *v0sv1.WorkloadSelector
		workloads, findings int
		vulnerabilities     int64
	}{
		{"omitted", nil, 8, 10, 3},
		{"explicit empty", &v0sv1.WorkloadSelector{}, 0, 0, 0},
		{"selected", apiWorkloadSelector(), 5, 5, 2},
		{"unknown", &v0sv1.WorkloadSelector{Workloads: []*v0sv1.WorkloadRef{{Environment: "unknown", Team: "other", Name: "app"}}}, 0, 0, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			legacyReq := &v0sv1.ListWorkloadsRequest{WorkloadSelector: tt.selector, PageSize: 1}
			var workloads []string
			for range 10 {
				resp, err := client.ListWorkloads(t.Context(), legacyReq)
				if err != nil {
					t.Fatal(err)
				}
				for _, w := range resp.GetWorkloads() {
					workloads = append(workloads, w.Environment+"/"+w.Team+"/"+w.Name)
				}
				if resp.TotalCount != nil || len(resp.GetCursors()) != 0 {
					t.Fatal("selector implicitly enabled overview mode")
				}
				if resp.GetNextPageToken() == "" {
					break
				}
				legacyReq.PageToken = resp.GetNextPageToken()
			}
			if len(workloads) != tt.workloads || len(slices.Compact(slices.Sorted(slices.Values(workloads)))) != tt.workloads {
				t.Fatalf("workloads: %v", workloads)
			}
			findingReq := &v0sv1.ListFindingsRequest{WorkloadSelector: tt.selector, PageSize: 1}
			var findingKeys []string
			for range 12 {
				resp, err := client.ListFindings(t.Context(), findingReq)
				if err != nil {
					t.Fatal(err)
				}
				var facetCount int64
				for _, c := range resp.GetPackageTypeCounts() {
					facetCount += c.GetCount()
					if tt.name == "selected" && ((c.Value == "npm" && c.Count != 2) || (c.Value == "maven" && c.Count != 3)) {
						t.Fatalf("selected facets: %v", resp.GetPackageTypeCounts())
					}
				}
				if facetCount != int64(tt.findings) {
					t.Fatalf("facets do not cover full selection: %v", resp)
				}
				for _, f := range resp.GetFindings() {
					w := f.GetWorkload()
					findingKeys = append(findingKeys, w.Environment+"/"+w.Team+"/"+w.Name+"/"+f.GetPurl())
				}
				if len(resp.GetCursors()) == 0 {
					break
				}
				findingReq.PageToken = resp.GetCursors()[len(resp.GetCursors())-1]
			}
			if len(findingKeys) != tt.findings || len(slices.Compact(slices.Sorted(slices.Values(findingKeys)))) != tt.findings {
				t.Fatalf("finding pages: %v", findingKeys)
			}
			vulnReq := &v0sv1.ListVulnerabilitiesRequest{WorkloadSelector: tt.selector, PageSize: 1}
			var ids []string
			for range 5 {
				resp, err := client.ListVulnerabilities(t.Context(), vulnReq)
				if err != nil || resp.GetTotalCount() != tt.vulnerabilities {
					t.Fatalf("vulnerability total: %v, %v", resp, err)
				}
				for _, v := range resp.GetVulnerabilities() {
					ids = append(ids, v.GetVulnerabilityId())
					if tt.name == "selected" {
						want := int64(2)
						if v.VulnerabilityId == "CVE-2" {
							want = 3
						}
						if v.FindingCount != want || v.AffectedWorkloadCount != want {
							t.Fatalf("shared image counts: %v", v)
						}
					}
				}
				if len(resp.GetCursors()) == 0 {
					break
				}
				vulnReq.PageToken = resp.GetCursors()[len(resp.GetCursors())-1]
			}
			if len(ids) != int(tt.vulnerabilities) || len(slices.Compact(slices.Sorted(slices.Values(ids)))) != int(tt.vulnerabilities) {
				t.Fatalf("vulnerability pages: %v", ids)
			}
			counts, err := client.CountFindings(t.Context(), &v0sv1.CountFindingsRequest{WorkloadSelector: tt.selector, GroupBy: v0sv1.CountFindingsRequest_GROUP_BY_WORKLOAD})
			if err != nil {
				t.Fatal(err)
			}
			var total int64
			for _, b := range counts.GetBuckets() {
				total += b.GetCount()
			}
			if total != int64(tt.findings) {
				t.Fatalf("counts: %v", counts)
			}
			for _, affected := range []bool{false, true} {
				req := &v0sv1.ListWorkloadsRequest{WorkloadSelector: tt.selector, PageSize: 1, Overview: &v0sv1.WorkloadOverviewOptions{AffectedOnly: affected}}
				want := tt.workloads
				if affected && want > 0 {
					want -= 2
				}
				var got int
				for range 10 {
					resp, err := client.ListWorkloads(t.Context(), req)
					if err != nil || resp.TotalCount == nil || resp.GetTotalCount() != int64(want) {
						t.Fatalf("overview: %v, %v", resp, err)
					}
					got += len(resp.GetWorkloads())
					for _, w := range resp.GetWorkloads() {
						if (w.Name == "clean" || w.Name == "unresolved") && w.GetFindingCounts().GetFindingCount() != 0 {
							t.Fatalf("zero-count workload: %v", w)
						}
					}
					if len(resp.GetCursors()) == 0 {
						break
					}
					req.PageToken = resp.GetCursors()[len(resp.GetCursors())-1]
				}
				if got != want {
					t.Fatalf("overview rows %d, want %d", got, want)
				}
			}
		})
	}
}

func TestWorkloadSelectorGRPCIntersections(t *testing.T) {
	client := workloadSelectorClient(t)
	selector := apiWorkloadSelector()
	for _, tt := range []struct {
		filter *v0sv1.FindingFilter
		count  int
	}{
		{&v0sv1.FindingFilter{Team: "team", Environment: "prod", Workload: "worker"}, 2},
		{&v0sv1.FindingFilter{Team: "other", Environment: "prod"}, 0},
		{&v0sv1.FindingFilter{PackageType: "npm"}, 2},
		{&v0sv1.FindingFilter{OnlyKnownExploited: true}, 3},
		{&v0sv1.FindingFilter{Suppressed: v0sv1.SuppressedFilter_SUPPRESSED_FILTER_ONLY}, 1},
	} {
		resp, err := client.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{Filter: tt.filter, WorkloadSelector: selector})
		if err != nil || len(resp.GetFindings()) != tt.count {
			t.Fatalf("filter intersection: %v, %v", resp, err)
		}
		counts, err := client.CountFindings(t.Context(), &v0sv1.CountFindingsRequest{Filter: tt.filter, WorkloadSelector: selector, GroupBy: v0sv1.CountFindingsRequest_GROUP_BY_SEVERITY})
		if err != nil {
			t.Fatal(err)
		}
		var count int64
		for _, b := range counts.GetBuckets() {
			count += b.GetCount()
		}
		if count != int64(tt.count) {
			t.Fatalf("count intersection: %v", counts)
		}
	}
	for _, affected := range []bool{false, true} {
		resp, err := client.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{Team: "team", WorkloadSelector: selector, Overview: &v0sv1.WorkloadOverviewOptions{AffectedOnly: affected, FindingFilter: &v0sv1.FindingFilter{PackageType: "missing"}}})
		want := int64(4)
		if affected {
			want = 0
		}
		if err != nil || resp.GetTotalCount() != want || int64(len(resp.GetWorkloads())) != want {
			t.Fatalf("scope/zero-count intersection: %v, %v", resp, err)
		}
	}
}

func TestWorkloadSelectorGRPCCursorsAndValidation(t *testing.T) {
	client := workloadSelectorClient(t)
	for _, tt := range []struct {
		name string
		list func(*v0sv1.WorkloadSelector, string) (string, error)
	}{
		{"workloads", func(s *v0sv1.WorkloadSelector, token string) (string, error) {
			resp, err := client.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{WorkloadSelector: s, PageToken: token, PageSize: 1})
			return resp.GetNextPageToken(), err
		}},
		{"findings", func(s *v0sv1.WorkloadSelector, token string) (string, error) {
			resp, err := client.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{WorkloadSelector: s, PageToken: token, PageSize: 1})
			return resp.GetNextPageToken(), err
		}},
		{"vulnerabilities", func(s *v0sv1.WorkloadSelector, token string) (string, error) {
			resp, err := client.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{WorkloadSelector: s, PageToken: token, PageSize: 1})
			return resp.GetNextPageToken(), err
		}},
		{"overview", func(s *v0sv1.WorkloadSelector, token string) (string, error) {
			resp, err := client.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{WorkloadSelector: s, PageToken: token, PageSize: 1, Overview: &v0sv1.WorkloadOverviewOptions{}})
			return resp.GetNextPageToken(), err
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			selector := apiWorkloadSelector()
			first, err := tt.list(selector, "")
			if err != nil || first == "" {
				t.Fatalf("initial cursor: %q, %v", first, err)
			}
			want, err := tt.list(selector, first)
			if err != nil {
				t.Fatal(err)
			}
			selector.Workloads = append(selector.Workloads, selector.Workloads...)
			slices.Reverse(selector.Workloads)
			if got, err := tt.list(selector, first); err != nil || got != want {
				t.Fatalf("normalized cursor: %q, %v", got, err)
			}
			changed := apiWorkloadSelector()
			changed.Workloads = append(changed.Workloads, &v0sv1.WorkloadRef{Environment: "dev", Team: "team", Name: "unknown"})
			for _, s := range []*v0sv1.WorkloadSelector{nil, {}, changed} {
				if _, err := tt.list(s, first); status.Code(err) != codes.InvalidArgument {
					t.Errorf("changed selector accepted: %v", err)
				}
			}
			old, err := tt.list(nil, "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := tt.list(nil, old); err != nil {
				t.Errorf("old cursor without selector: %v", err)
			}
			if _, err := tt.list(selector, old); status.Code(err) != codes.InvalidArgument {
				t.Errorf("old cursor with selector: %v", err)
			}
			for _, w := range []*v0sv1.WorkloadRef{
				nil, {}, {Environment: "dev", Team: "team"}, {Environment: "dev", Name: "app"},
				{Team: "team", Name: "app"}, {Environment: "dev", Team: "team", Name: " "},
			} {
				invalid := &v0sv1.WorkloadSelector{Workloads: []*v0sv1.WorkloadRef{w}}
				if _, err := tt.list(invalid, ""); status.Code(err) != codes.InvalidArgument {
					t.Errorf("invalid selector accepted: %v", err)
				}
				if _, err := client.CountFindings(t.Context(), &v0sv1.CountFindingsRequest{WorkloadSelector: invalid, GroupBy: v0sv1.CountFindingsRequest_GROUP_BY_TEAM}); status.Code(err) != codes.InvalidArgument {
					t.Errorf("invalid selector count: %v", err)
				}
			}
		})
	}
}

func TestWorkloadSelectorGRPCSize(t *testing.T) {
	client := workloadSelectorClient(t)
	selector := &v0sv1.WorkloadSelector{}
	for i := range 25_000 {
		selector.Workloads = append(selector.Workloads, &v0sv1.WorkloadRef{Environment: "dev", Team: "team", Name: fmt.Sprintf("unknown-%05d", i)})
	}
	selector.Workloads = append(selector.Workloads, apiWorkloadSelector().Workloads...)
	resp, err := client.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{WorkloadSelector: selector, Overview: &v0sv1.WorkloadOverviewOptions{}})
	if err != nil || resp.GetTotalCount() != 5 || len(resp.GetWorkloads()) != 5 {
		t.Fatalf("large selection: %v, %v", resp, err)
	}
	oversized := &v0sv1.WorkloadSelector{Workloads: []*v0sv1.WorkloadRef{{Environment: "dev", Team: "team", Name: strings.Repeat("x", 4*1024*1024)}}}
	if _, err := client.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{WorkloadSelector: oversized}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("gRPC request limit: %v", err)
	}
}
