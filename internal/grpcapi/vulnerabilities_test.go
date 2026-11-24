package grpcapi_test

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestVulnerabilityOverviewContract(t *testing.T) {
	s := newServer(t, `
		INSERT INTO vulnerabilities (id, db_version) VALUES ('CVE-2', now());
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, fixed_version, status, severity)
		SELECT id, 'CVE-2', p, split_part(p, '@', 1), '1', '2', 'affected', 'CRITICAL'
		FROM images CROSS JOIN (VALUES ('pkg:npm/a@1'), ('pkg:maven/example/lib@1')) packages(p);
	`)
	for _, field := range []v0sv1.VulnerabilityOrderBy_Field{
		v0sv1.VulnerabilityOrderBy_FIELD_SEVERITY,
		v0sv1.VulnerabilityOrderBy_FIELD_VULNERABILITY_ID,
		v0sv1.VulnerabilityOrderBy_FIELD_AFFECTED_WORKLOAD_COUNT,
	} {
		for _, direction := range []v0sv1.VulnerabilityOrderBy_Direction{v0sv1.VulnerabilityOrderBy_DIRECTION_ASC, v0sv1.VulnerabilityOrderBy_DIRECTION_DESC} {
			req := &v0sv1.ListVulnerabilitiesRequest{
				Filter: &v0sv1.FindingFilter{Team: "team"}, PageSize: 1,
				OrderBy: &v0sv1.VulnerabilityOrderBy{Field: field, Direction: direction},
			}
			wire, err := proto.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			decoded := new(v0sv1.ListVulnerabilitiesRequest)
			if err := proto.Unmarshal(wire, decoded); err != nil {
				t.Fatal(err)
			}
			var ids []string
			for range 3 {
				resp, err := s.ListVulnerabilities(t.Context(), decoded)
				if err != nil {
					t.Fatal(err)
				}
				if resp.GetTotalCount() != 2 || len(resp.GetVulnerabilities()) != 1 || len(resp.GetCursors()) != 1 {
					t.Fatalf("unexpected page: %v", resp)
				}
				row := resp.GetVulnerabilities()[0]
				ids = append(ids, row.GetVulnerabilityId())
				wantFindings, wantSeverity := int64(4), v0sv1.Severity_SEVERITY_HIGH
				if row.GetVulnerabilityId() == "CVE-2" {
					wantFindings, wantSeverity = 8, v0sv1.Severity_SEVERITY_CRITICAL
				}
				if row.GetFindingCount() != wantFindings || row.GetAffectedWorkloadCount() != 4 || row.GetSeverity() != wantSeverity {
					t.Fatalf("incorrect summary: %v", row)
				}
				decoded.PageToken = resp.GetCursors()[0]
				if resp.GetNextPageToken() == "" {
					empty, err := s.ListVulnerabilities(t.Context(), decoded)
					if err != nil || len(empty.GetVulnerabilities()) != 0 || empty.GetTotalCount() != 2 || len(empty.GetCursors()) != 0 || empty.GetNextPageToken() != "" {
						t.Fatalf("empty last page: %v, %v", empty, err)
					}
					break
				}
				if resp.GetNextPageToken() != decoded.PageToken {
					t.Fatal("next token differs from row cursor")
				}
			}
			want := []string{"CVE-1", "CVE-2"}
			if direction == v0sv1.VulnerabilityOrderBy_DIRECTION_DESC && field != v0sv1.VulnerabilityOrderBy_FIELD_AFFECTED_WORKLOAD_COUNT {
				slices.Reverse(want)
			}
			if !slices.Equal(ids, want) {
				t.Errorf("%v %v: %v, want %v", field, direction, ids, want)
			}
			decoded.Filter = &v0sv1.FindingFilter{Team: "other"}
			if _, err := s.ListVulnerabilities(t.Context(), decoded); status.Code(err) != codes.InvalidArgument {
				t.Errorf("changed filter: %v", err)
			}
		}
	}
	first, err := s.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{PageSize: 1})
	if err != nil || len(first.GetVulnerabilities()) != 1 || first.GetVulnerabilities()[0].GetVulnerabilityId() != "CVE-2" {
		t.Fatalf("default severity DESC: %v, %v", first, err)
	}
	next, err := s.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{
		PageToken: first.GetNextPageToken(),
		OrderBy:   &v0sv1.VulnerabilityOrderBy{Field: v0sv1.VulnerabilityOrderBy_FIELD_SEVERITY, Direction: v0sv1.VulnerabilityOrderBy_DIRECTION_DESC},
	})
	if err != nil || len(next.GetVulnerabilities()) != 1 || next.GetVulnerabilities()[0].GetVulnerabilityId() != "CVE-1" {
		t.Fatalf("explicit default continuation: %v, %v", next, err)
	}
	for _, filter := range []*v0sv1.FindingFilter{
		{PackageType: "maven"}, {HasFix: true}, {OnlyKnownExploited: true},
	} {
		list, err := s.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{Filter: filter})
		if err != nil || list.GetTotalCount() != 1 || len(list.GetVulnerabilities()) != 1 || list.GetVulnerabilities()[0].GetVulnerabilityId() != "CVE-2" {
			t.Errorf("filter %v: %v, %v", filter, list, err)
		}
	}
}

func TestVulnerabilityOverviewErrors(t *testing.T) {
	s := newServer(t)
	for _, order := range []*v0sv1.VulnerabilityOrderBy{
		{}, {Field: v0sv1.VulnerabilityOrderBy_FIELD_SEVERITY},
		{Direction: v0sv1.VulnerabilityOrderBy_DIRECTION_ASC},
		{Field: 99, Direction: v0sv1.VulnerabilityOrderBy_DIRECTION_ASC},
		{Field: v0sv1.VulnerabilityOrderBy_FIELD_SEVERITY, Direction: 99},
	} {
		if _, err := s.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{OrderBy: order}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("invalid order %v: %v", order, err)
		}
	}
	for _, filter := range []*v0sv1.FindingFilter{
		{Workload: "app"}, {Package: "not-a-purl"}, {PackageType: "npm/no"},
		{Severities: []v0sv1.Severity{0}}, {VulnerabilityIds: []string{" "}}, {Suppressed: 99},
	} {
		if _, err := s.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{Filter: filter}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("invalid filter %v: %v", filter, err)
		}
	}
	for _, token := range []string{"garbage!", base64.RawURLEncoding.EncodeToString([]byte(`{"version":99}`))} {
		if _, err := s.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{PageToken: token}); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "restart pagination") {
			t.Errorf("invalid cursor %q: %v", token, err)
		}
	}
	noKEV := newServer(t, `DELETE FROM kev`)
	if _, err := noKEV.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{}); err != nil {
		t.Errorf("overview without KEV filter: %v", err)
	}
	if _, err := noKEV.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{Filter: &v0sv1.FindingFilter{OnlyKnownExploited: true}}); status.Code(err) != codes.Unavailable {
		t.Errorf("KEV filter without catalog: %v", err)
	}
}
