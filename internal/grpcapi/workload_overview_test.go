package grpcapi_test

import (
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/grpcapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	client := serveVulnerabilities(t, newWorkloadOverviewServer(t))
	want := []string{"dev/app", "dev/clean", "dev/failed", "dev/missing", "dev/pending", "dev/unresolved", "dev/worker", "prod/app", "prod/worker"}
	for _, size := range []int32{1, 2} {
		req := &v0sv1.ListWorkloadsRequest{Team: "team", PageSize: size, Overview: &v0sv1.WorkloadOverviewOptions{}}
		var got []string
		for range 10 {
			resp, err := client.ListWorkloads(t.Context(), req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.TotalCount == nil || resp.GetTotalCount() != 9 || len(resp.GetWorkloads()) > int(size) {
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
			if resp.GetNextPageToken() != "" && resp.GetNextPageToken() == req.PageToken {
				t.Fatal("next token did not advance")
			}
			req.PageToken = resp.GetNextPageToken()
			if req.PageToken == "" {
				break
			}
		}
		if !slices.Equal(got, want) || req.PageToken != "" {
			t.Fatalf("size %d: %v, want %v", size, got, want)
		}
	}
}

func TestWorkloadOverviewSelectionAndFilters(t *testing.T) {
	s := newWorkloadOverviewServer(t)
	one, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{Team: "team", Environment: "dev", Workload: "app", Overview: &v0sv1.WorkloadOverviewOptions{}})
	if err != nil || one.GetTotalCount() != 1 || len(one.GetWorkloads()) != 1 {
		t.Fatalf("existing scope selection: %v, %v", one, err)
	}
}

func TestWorkloadOverviewBatchContinuesPastPageLimit(t *testing.T) {
	client := serveVulnerabilities(t, newServer(t, `
		UPDATE images SET sbom_state = 'fetched', sbom = '', scanned_at = '2026-01-02';
		INSERT INTO kev (cve, date_added, known_ransomware_campaign) VALUES ('CVE-1', '2026-01-02', false);
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, status, severity)
		SELECT id, 'CVE-1', 'pkg:npm/other@1', 'pkg:npm/other', '1', 'affected', 'LOW' FROM images;
		INSERT INTO vulnerabilities (id, db_version) VALUES ('CVE-2', now());
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, status, severity)
		SELECT id, 'CVE-2', 'pkg:maven/example/lib@1', 'pkg:maven/example/lib', '1', 'affected', 'UNKNOWN' FROM images;
		INSERT INTO workloads (environment, team, name, image_reference, image_id)
		SELECT 'dev', 'team', 'batch-' || lpad(n::text, 4, '0'), 'repo/app:1', id
		FROM images CROSS JOIN generate_series(0, 1000) n;
	`))
	const batchSize = 1001
	selector := &v0sv1.WorkloadSelector{}
	for i := range batchSize {
		selector.Workloads = append(selector.Workloads, &v0sv1.WorkloadRef{
			Environment: "dev", Team: "team", Name: fmt.Sprintf("batch-%04d", i),
		})
	}
	req := &v0sv1.ListWorkloadsRequest{
		WorkloadSelector: selector, PageSize: batchSize,
		Overview: &v0sv1.WorkloadOverviewOptions{FindingFilter: &v0sv1.FindingFilter{PackageType: "npm"}},
	}
	var got int
	for _, size := range []int{1000, 1} {
		resp, err := client.ListWorkloads(t.Context(), req)
		if err != nil || resp.TotalCount == nil || resp.GetTotalCount() != batchSize || len(resp.GetWorkloads()) != size {
			t.Fatalf("batch page: %d rows, total %d, error %v", len(resp.GetWorkloads()), resp.GetTotalCount(), err)
		}
		for _, w := range resp.GetWorkloads() {
			c := w.GetFindingCounts()
			if w.GetName() != selector.Workloads[got].GetName() ||
				c.GetFindingCount() != 2 || c.GetUniqueVulnerabilityCount() != 1 ||
				c.GetUniqueKevVulnerabilityCount() != 1 || c.GetSeverityCounts().GetHigh() != 1 ||
				w.GetImage().GetStatus() != v0sv1.ImageStatus_IMAGE_STATUS_SCANNED {
				t.Fatalf("batch row %d: %v", got, w)
			}
			got++
		}
		req.PageToken = resp.GetNextPageToken()
		if (req.PageToken != "") != (got < batchSize) {
			t.Fatalf("unexpected continuation after %d rows", got)
		}
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
	first, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{PageSize: 1, Overview: &v0sv1.WorkloadOverviewOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	for _, req := range []*v0sv1.ListWorkloadsRequest{
		{PageToken: first.GetNextPageToken()},
		{Team: "other", PageToken: first.GetNextPageToken(), Overview: &v0sv1.WorkloadOverviewOptions{}},
		{PageToken: first.GetNextPageToken(), Overview: &v0sv1.WorkloadOverviewOptions{FindingFilter: &v0sv1.FindingFilter{PackageType: "npm"}}},
	} {
		if _, err := s.ListWorkloads(t.Context(), req); status.Code(err) != codes.InvalidArgument {
			t.Errorf("incompatible cursor parameters: %v", err)
		}
	}
	legacy, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{PageSize: 1})
	wantLegacyToken := base64.RawURLEncoding.EncodeToString([]byte(`{"e":"dev","t":"team","w":"app"}`))
	if err != nil || legacy.GetNextPageToken() != wantLegacyToken || legacy.TotalCount != nil || legacy.GetWorkloads()[0].GetFindingCounts() != nil {
		t.Fatalf("legacy response changed: %v, %v", legacy, err)
	}
	if _, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{PageToken: wantLegacyToken}); err != nil {
		t.Fatalf("legacy continuation: %v", err)
	}
	v1Token := base64.RawURLEncoding.EncodeToString([]byte(`{"version":1,"operation":"workload-overview","binding":"old","environment":"dev","team":"team","name":"app"}`))
	for _, token := range []string{wantLegacyToken, v1Token, "garbage!", base64.RawURLEncoding.EncodeToString([]byte(`{"version":99}`))} {
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
