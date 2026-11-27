package grpcapi_test

import (
	"context"
	"encoding/base64"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/database/databasetest"
	"github.com/nais/v0s/internal/grpcapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func assertBidirectionalRPC[T proto.Message](t *testing.T,
	fetch func(int32, string, v0sv1.PageDirection) ([]T, []string, string, *v0sv1.PageInfo, error),
) {
	t.Helper()
	all, cursors, _, _, err := fetch(100, "", v0sv1.PageDirection_PAGE_DIRECTION_UNSPECIFIED)
	if err != nil {
		t.Fatal(err)
	}
	check := func(size int32, token string, direction v0sv1.PageDirection, start, end int) {
		t.Helper()
		rows, tokens, next, info, err := fetch(size, token, direction)
		if err != nil {
			t.Fatal(err)
		}
		previous, following := start > 0, end < len(all)
		if start == end && token != "" {
			previous = direction != v0sv1.PageDirection_PAGE_DIRECTION_BACKWARD
			following = !previous
		}
		if info == nil || info.GetHasPreviousPage() != previous || info.GetHasNextPage() != following ||
			!slices.Equal(tokens, cursors[start:end]) ||
			!slices.EqualFunc(rows, all[start:end], func(a, b T) bool { return proto.Equal(a, b) }) {
			t.Fatalf("size=%d token=%q direction=%s: rows=%v info=%v; want [%d:%d] previous=%t next=%t",
				size, token, direction, rows, info, start, end, previous, following)
		}
		wantNext := ""
		if end > start && following {
			wantNext = cursors[end-1]
		}
		if next != wantNext {
			t.Fatalf("next token differs from forward end cursor: %q, want %q", next, wantNext)
		}
	}
	check(3, "", v0sv1.PageDirection_PAGE_DIRECTION_FORWARD, 0, min(3, len(all)))
	check(3, "", v0sv1.PageDirection_PAGE_DIRECTION_BACKWARD, max(0, len(all)-3), len(all))
	for i, cursor := range cursors {
		check(3, cursor, v0sv1.PageDirection_PAGE_DIRECTION_FORWARD, i+1, min(len(all), i+4))
		check(3, cursor, v0sv1.PageDirection_PAGE_DIRECTION_BACKWARD, max(0, i-3), i)
	}
	if len(all) > 3 {
		check(3, cursors[2], v0sv1.PageDirection_PAGE_DIRECTION_FORWARD, 3, min(6, len(all)))
		check(3, cursors[3], v0sv1.PageDirection_PAGE_DIRECTION_BACKWARD, 0, 3)
	}
	if _, _, _, _, err := fetch(3, "", 99); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid page_direction: %v", err)
	}
}

func TestBidirectionalPaginationOverGRPC(t *testing.T) {
	db, url := databasetest.NewWithURL(t)
	conn, err := pgx.Connect(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	_, err = conn.Exec(t.Context(), `
		INSERT INTO images (id, name, digest) OVERRIDING SYSTEM VALUE VALUES (1, 'repo/app', 'a');
		INSERT INTO workloads (environment, team, name, image_reference, image_id) VALUES
			('dev', 'team', 'app', 'repo/app:1', 1),
			('dev', 'team', 'worker', 'repo/app:1', 1),
			('prod', 'team', 'app', 'repo/app:1', 1);
		INSERT INTO vulnerabilities (id, db_version)
			SELECT id, now() FROM unnest(ARRAY['A','B','C','D','E','F']) id;
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, status, severity)
			SELECT 1, id, p, split_part(p, '@', 1), '1', 'affected', severity
			FROM (VALUES ('A','pkg:maven/a@1','UNKNOWN'), ('B','pkg:npm/b@1','LOW'),
				('C','pkg:npm/c@1','MEDIUM'), ('D','pkg:npm/d@1','HIGH'),
				('D','pkg:npm/z@1','HIGH'), ('E','pkg:npm/e@1','CRITICAL'),
				('F','pkg:npm/f@1','HIGH')) v(id,p,severity);
		INSERT INTO suppressions (team, environment, workload, image_name, package_key, vulnerability_id, state, detail, updated_by)
			SELECT w.team, w.environment, w.name, 'repo/app', f.package_key, f.vulnerability_id, 'accepted_risk', 'assessed', 'user'
			FROM workloads w JOIN findings f ON f.image_id=w.image_id;
		INSERT INTO kev (cve, date_added, known_ransomware_campaign) VALUES ('E', '2026-01-02', false);
	`)
	if err != nil {
		t.Fatal(err)
	}
	server := grpcapi.New(db, slog.New(slog.DiscardHandler))
	client := serveVulnerabilities(t, server)
	suppressionClient := serve(t, server)
	filter := &v0sv1.FindingFilter{Suppressed: v0sv1.SuppressedFilter_SUPPRESSED_FILTER_INCLUDE}
	for _, field := range []v0sv1.FindingOrderBy_Field{
		v0sv1.FindingOrderBy_FIELD_UNSPECIFIED, v0sv1.FindingOrderBy_FIELD_SEVERITY, v0sv1.FindingOrderBy_FIELD_VULNERABILITY_ID,
	} {
		for _, direction := range []v0sv1.FindingOrderBy_Direction{v0sv1.FindingOrderBy_DIRECTION_ASC, v0sv1.FindingOrderBy_DIRECTION_DESC} {
			var order *v0sv1.FindingOrderBy
			if field != v0sv1.FindingOrderBy_FIELD_UNSPECIFIED {
				order = &v0sv1.FindingOrderBy{Field: field, Direction: direction}
			}
			t.Run("findings/"+field.String()+"/"+direction.String(), func(t *testing.T) {
				assertBidirectionalRPC(t, func(size int32, token string, traversal v0sv1.PageDirection) ([]*v0sv1.Finding, []string, string, *v0sv1.PageInfo, error) {
					resp, err := client.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{
						Filter: filter, OrderBy: order, PageSize: size, PageToken: token, PageDirection: traversal,
					})
					if err == nil && (len(resp.GetPackageTypeCounts()) != 2 ||
						resp.GetPackageTypeCounts()[0].GetCount() != 3 || resp.GetPackageTypeCounts()[1].GetCount() != 18) {
						t.Fatalf("facets changed: %v", resp)
					}
					return resp.GetFindings(), resp.GetCursors(), resp.GetNextPageToken(), resp.GetPageInfo(), err
				})
			})
		}
	}
	for _, field := range []v0sv1.VulnerabilityOrderBy_Field{
		v0sv1.VulnerabilityOrderBy_FIELD_UNSPECIFIED, v0sv1.VulnerabilityOrderBy_FIELD_SEVERITY,
		v0sv1.VulnerabilityOrderBy_FIELD_VULNERABILITY_ID, v0sv1.VulnerabilityOrderBy_FIELD_AFFECTED_WORKLOAD_COUNT,
	} {
		for _, direction := range []v0sv1.VulnerabilityOrderBy_Direction{v0sv1.VulnerabilityOrderBy_DIRECTION_ASC, v0sv1.VulnerabilityOrderBy_DIRECTION_DESC} {
			var order *v0sv1.VulnerabilityOrderBy
			if field != v0sv1.VulnerabilityOrderBy_FIELD_UNSPECIFIED {
				order = &v0sv1.VulnerabilityOrderBy{Field: field, Direction: direction}
			}
			t.Run("vulnerabilities/"+field.String()+"/"+direction.String(), func(t *testing.T) {
				assertBidirectionalRPC(t, func(size int32, token string, traversal v0sv1.PageDirection) ([]*v0sv1.VulnerabilitySummary, []string, string, *v0sv1.PageInfo, error) {
					resp, err := client.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{
						Filter: filter, OrderBy: order, PageSize: size, PageToken: token, PageDirection: traversal,
					})
					if err == nil && resp.GetTotalCount() != 6 {
						t.Fatalf("total changed: %v", resp)
					}
					return resp.GetVulnerabilities(), resp.GetCursors(), resp.GetNextPageToken(), resp.GetPageInfo(), err
				})
			})
		}
	}
	t.Run("suppressions", func(t *testing.T) {
		assertBidirectionalRPC(t, func(size int32, token string, traversal v0sv1.PageDirection) ([]*v0sv1.Suppression, []string, string, *v0sv1.PageInfo, error) {
			resp, err := suppressionClient.ListSuppressions(t.Context(), &v0sv1.ListSuppressionsRequest{
				PageSize: size, PageToken: token, PageDirection: traversal,
			})
			return resp.GetSuppressions(), resp.GetCursors(), resp.GetNextPageToken(), resp.GetPageInfo(), err
		})
	})

	scope := &v0sv1.FindingFilter{Team: "team", Environment: "dev", Workload: "app",
		VulnerabilityIds: []string{"A"}, Suppressed: v0sv1.SuppressedFilter_SUPPRESSED_FILTER_INCLUDE}
	f, err := client.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{Filter: scope})
	if err != nil {
		t.Fatal(err)
	}
	v, err := client.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{Filter: scope})
	if err != nil {
		t.Fatal(err)
	}
	s, err := suppressionClient.ListSuppressions(t.Context(), &v0sv1.ListSuppressionsRequest{
		Team: "team", Environment: "dev", Workload: "app", VulnerabilityId: "A",
	})
	if err != nil || len(f.GetCursors()) != 1 || len(v.GetCursors()) != 1 || len(s.GetCursors()) != 1 {
		t.Fatalf("boundary cursors: %v %v %v, %v", f, v, s, err)
	}
	if _, err := conn.Exec(t.Context(), `DELETE FROM findings WHERE vulnerability_id='A'; DELETE FROM suppressions WHERE vulnerability_id='A'`); err != nil {
		t.Fatal(err)
	}
	for _, direction := range []v0sv1.PageDirection{v0sv1.PageDirection_PAGE_DIRECTION_FORWARD, v0sv1.PageDirection_PAGE_DIRECTION_BACKWARD} {
		rf, err := client.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{Filter: scope, PageToken: f.GetCursors()[0], PageDirection: direction})
		if err != nil || len(rf.GetFindings()) != 0 || !proto.Equal(rf.GetPageInfo(), &v0sv1.PageInfo{}) || len(rf.GetPackageTypeCounts()) != 0 {
			t.Fatalf("deleted finding boundary: %v, %v", rf, err)
		}
		rv, err := client.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{Filter: scope, PageToken: v.GetCursors()[0], PageDirection: direction})
		if err != nil || len(rv.GetVulnerabilities()) != 0 || rv.GetTotalCount() != 0 || !proto.Equal(rv.GetPageInfo(), &v0sv1.PageInfo{}) {
			t.Fatalf("deleted overview boundary: %v, %v", rv, err)
		}
		rs, err := suppressionClient.ListSuppressions(t.Context(), &v0sv1.ListSuppressionsRequest{
			Team: "team", Environment: "dev", Workload: "app", VulnerabilityId: "A",
			PageToken: s.GetCursors()[0], PageDirection: direction,
		})
		if err != nil || len(rs.GetSuppressions()) != 0 || !proto.Equal(rs.GetPageInfo(), &v0sv1.PageInfo{}) {
			t.Fatalf("deleted suppression boundary: %v, %v", rs, err)
		}
		if _, err := client.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{Filter: filter, PageToken: f.GetCursors()[0], PageDirection: direction}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("changed finding scope: %v", err)
		}
		if _, err := client.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{
			Filter: scope, PageToken: f.GetCursors()[0], PageDirection: direction,
			OrderBy: &v0sv1.FindingOrderBy{Field: v0sv1.FindingOrderBy_FIELD_SEVERITY, Direction: v0sv1.FindingOrderBy_DIRECTION_ASC},
		}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("changed finding order: %v", err)
		}
		if _, err := client.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{
			Filter: scope, PageToken: f.GetCursors()[0], PageDirection: direction, WorkloadSelector: &v0sv1.WorkloadSelector{},
		}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("changed finding selector: %v", err)
		}
		if _, err := client.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{Filter: filter, PageToken: v.GetCursors()[0], PageDirection: direction}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("changed overview scope: %v", err)
		}
		if _, err := client.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{
			Filter: scope, PageToken: v.GetCursors()[0], PageDirection: direction,
			OrderBy: &v0sv1.VulnerabilityOrderBy{Field: v0sv1.VulnerabilityOrderBy_FIELD_VULNERABILITY_ID, Direction: v0sv1.VulnerabilityOrderBy_DIRECTION_ASC},
		}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("changed overview order: %v", err)
		}
		if _, err := client.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{
			Filter: scope, PageToken: v.GetCursors()[0], PageDirection: direction, WorkloadSelector: &v0sv1.WorkloadSelector{},
		}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("changed overview selector: %v", err)
		}
		if _, err := suppressionClient.ListSuppressions(t.Context(), &v0sv1.ListSuppressionsRequest{PageToken: s.GetCursors()[0], PageDirection: direction}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("changed suppression scope: %v", err)
		}
	}
	t.Run("empty findings", func(t *testing.T) {
		assertBidirectionalRPC(t, func(size int32, token string, traversal v0sv1.PageDirection) ([]*v0sv1.Finding, []string, string, *v0sv1.PageInfo, error) {
			resp, err := client.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{
				Filter: scope, PageSize: size, PageToken: token, PageDirection: traversal,
			})
			return resp.GetFindings(), resp.GetCursors(), resp.GetNextPageToken(), resp.GetPageInfo(), err
		})
	})
	t.Run("empty vulnerabilities", func(t *testing.T) {
		assertBidirectionalRPC(t, func(size int32, token string, traversal v0sv1.PageDirection) ([]*v0sv1.VulnerabilitySummary, []string, string, *v0sv1.PageInfo, error) {
			resp, err := client.ListVulnerabilities(t.Context(), &v0sv1.ListVulnerabilitiesRequest{
				Filter: scope, PageSize: size, PageToken: token, PageDirection: traversal,
			})
			return resp.GetVulnerabilities(), resp.GetCursors(), resp.GetNextPageToken(), resp.GetPageInfo(), err
		})
	})
	t.Run("empty suppressions", func(t *testing.T) {
		assertBidirectionalRPC(t, func(size int32, token string, traversal v0sv1.PageDirection) ([]*v0sv1.Suppression, []string, string, *v0sv1.PageInfo, error) {
			resp, err := suppressionClient.ListSuppressions(t.Context(), &v0sv1.ListSuppressionsRequest{
				Team: "missing", PageSize: size, PageToken: token, PageDirection: traversal,
			})
			return resp.GetSuppressions(), resp.GetCursors(), resp.GetNextPageToken(), resp.GetPageInfo(), err
		})
	})
}

func TestFindingOrderContract(t *testing.T) {
	s := newServer(t, `
		INSERT INTO vulnerabilities (id, db_version) VALUES ('CVE-2', now());
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, status, severity)
		SELECT id, 'CVE-2', 'pkg:maven/example/lib@1', 'pkg:maven/example/lib', '1', 'affected', 'CRITICAL' FROM images;
	`)
	for _, field := range []v0sv1.FindingOrderBy_Field{v0sv1.FindingOrderBy_FIELD_SEVERITY, v0sv1.FindingOrderBy_FIELD_VULNERABILITY_ID} {
		for _, direction := range []v0sv1.FindingOrderBy_Direction{v0sv1.FindingOrderBy_DIRECTION_ASC, v0sv1.FindingOrderBy_DIRECTION_DESC} {
			req := &v0sv1.ListFindingsRequest{
				Filter: &v0sv1.FindingFilter{Team: "team"}, PageSize: 1,
				OrderBy: &v0sv1.FindingOrderBy{Field: field, Direction: direction},
			}
			wire, err := proto.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			decoded := new(v0sv1.ListFindingsRequest)
			if err := proto.Unmarshal(wire, decoded); err != nil {
				t.Fatal(err)
			}
			var ids []string
			for range 9 {
				resp, err := s.ListFindings(t.Context(), decoded)
				if err != nil {
					t.Fatal(err)
				}
				if len(resp.GetFindings()) != 1 || len(resp.GetCursors()) != 1 || len(resp.GetPackageTypeCounts()) != 2 {
					t.Fatalf("unexpected page: %v", resp)
				}
				for _, count := range resp.GetPackageTypeCounts() {
					if count.GetCount() != 4 {
						t.Fatalf("facet limited to page: %v", resp)
					}
				}
				ids = append(ids, resp.GetFindings()[0].GetVulnerabilityId())
				if resp.GetNextPageToken() == "" {
					break
				}
				if resp.GetNextPageToken() != resp.GetCursors()[0] {
					t.Fatal("next token differs from element cursor")
				}
				decoded.PageToken = resp.GetNextPageToken()
			}
			want := []string{"CVE-1", "CVE-1", "CVE-1", "CVE-1", "CVE-2", "CVE-2", "CVE-2", "CVE-2"}
			if direction == v0sv1.FindingOrderBy_DIRECTION_DESC {
				slices.Reverse(want)
			}
			if !slices.Equal(ids, want) {
				t.Fatalf("field %v direction %v: %v, want %v", field, direction, ids, want)
			}
			decoded.OrderBy = nil
			if _, err := s.ListFindings(t.Context(), decoded); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("changed sort: %v", err)
			}
			decoded.OrderBy = req.OrderBy
			decoded.Filter = &v0sv1.FindingFilter{Environment: "dev"}
			if _, err := s.ListFindings(t.Context(), decoded); status.Code(err) != codes.InvalidArgument {
				t.Fatalf("changed filter: %v", err)
			}
		}
	}
	for _, order := range []*v0sv1.FindingOrderBy{
		{}, {Field: v0sv1.FindingOrderBy_FIELD_SEVERITY},
		{Direction: v0sv1.FindingOrderBy_DIRECTION_ASC},
		{Field: 99, Direction: v0sv1.FindingOrderBy_DIRECTION_ASC},
		{Field: v0sv1.FindingOrderBy_FIELD_SEVERITY, Direction: 99},
	} {
		if _, err := s.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{OrderBy: order}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("invalid order %v: %v", order, err)
		}
	}
	token := base64.RawURLEncoding.EncodeToString([]byte(`{"e":"dev","t":"team","w":"app","v":"CVE-1","p":"pkg:npm/lodash@4.17.20"}`))
	if _, err := s.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{PageToken: token}); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "restart pagination") {
		t.Errorf("legacy cursor: %v", err)
	}
	listed, err := s.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{
		Filter:    &v0sv1.FindingFilter{Suppressed: v0sv1.SuppressedFilter_SUPPRESSED_FILTER_EXCLUDE},
		PageToken: listed.GetCursors()[0],
	}); err != nil {
		t.Errorf("equivalent default filter: %v", err)
	}
}

func TestReadScope(t *testing.T) {
	s := newServer(t, `
		INSERT INTO workloads (environment, team, name, image_reference, image_id)
		SELECT 'prod', 'other-team', 'app', 'repo/app:1', id FROM images;
		INSERT INTO components (image_id, purl, package_key, name, version)
		SELECT id, 'pkg:npm/lodash@4.17.20', 'pkg:npm/lodash', 'lodash', '4.17.20' FROM images;`)
	tests := []struct {
		name                          string
		team, environment, nameFilter string
		want                          int
	}{
		{name: "tenant", want: 5},
		{name: "one team", team: "team", want: 4},
		{name: "one environment", environment: "prod", want: 3},
		{name: "team and environment", team: "team", environment: "prod", want: 2},
		{name: "one workload", team: "team", environment: "prod", nameFilter: "app", want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			workloads, err := s.ListWorkloads(ctx, &v0sv1.ListWorkloadsRequest{Team: tt.team, Environment: tt.environment, Workload: tt.nameFilter})
			if err != nil || len(workloads.GetWorkloads()) != tt.want {
				t.Fatalf("workloads = %v, %v; want %d", workloads, err, tt.want)
			}
			filter := &v0sv1.FindingFilter{Team: tt.team, Environment: tt.environment, Workload: tt.nameFilter}
			findings, err := s.ListFindings(ctx, &v0sv1.ListFindingsRequest{Filter: filter})
			if err != nil || len(findings.GetFindings()) != tt.want {
				t.Fatalf("findings = %v, %v; want %d", findings, err, tt.want)
			}
			counts, err := s.CountFindings(ctx, &v0sv1.CountFindingsRequest{Filter: filter, GroupBy: v0sv1.CountFindingsRequest_GROUP_BY_SEVERITY})
			if err != nil || len(counts.GetBuckets()) != 1 || counts.GetBuckets()[0].GetCount() != int64(tt.want) {
				t.Errorf("counts = %v, %v; want %d", counts, err, tt.want)
			}
		})
	}

	for team, want := range map[string]int{"": 5, "team": 4, "other-team": 1, "missing": 0} {
		matches, err := s.SearchComponents(t.Context(), &v0sv1.SearchComponentsRequest{Query: "lodash", Team: team})
		if err != nil {
			t.Fatal(err)
		}
		var count int
		for _, match := range matches.GetMatches() {
			count += len(match.GetWorkloads())
			for _, workload := range match.GetWorkloads() {
				if team != "" && workload.GetTeam() != team {
					t.Errorf("component search for %q included %v", team, workload)
				}
			}
		}
		if count != want {
			t.Errorf("component search for %q returned %d workloads, want %d", team, count, want)
		}
	}

	for _, filter := range []*v0sv1.FindingFilter{
		{Workload: "app"},
		{Workload: "app", Team: "team"},
		{Workload: "app", Environment: "prod"},
	} {
		if _, err := s.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{Filter: filter}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("findings with incomplete scope %v: %v", filter, err)
		}
		if _, err := s.CountFindings(t.Context(), &v0sv1.CountFindingsRequest{Filter: filter, GroupBy: v0sv1.CountFindingsRequest_GROUP_BY_SEVERITY}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("count with incomplete scope %v: %v", filter, err)
		}
		if _, err := s.ListWorkloads(t.Context(), &v0sv1.ListWorkloadsRequest{Team: filter.Team, Environment: filter.Environment, Workload: filter.Workload}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("workloads with incomplete scope %v: %v", filter, err)
		}
		if _, err := s.ListSuppressions(t.Context(), &v0sv1.ListSuppressionsRequest{Team: filter.Team, Environment: filter.Environment, Workload: filter.Workload}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("suppressions with incomplete scope %v: %v", filter, err)
		}
	}
}

func TestLegacyTeamFiltersAreRejected(t *testing.T) {
	s := newServer(t)
	tests := []struct {
		name    string
		message proto.Message
		field   protowire.Number
		call    func(proto.Message) error
	}{
		{name: "workloads", message: &v0sv1.ListWorkloadsRequest{}, field: 1, call: func(m proto.Message) error {
			_, err := s.ListWorkloads(t.Context(), m.(*v0sv1.ListWorkloadsRequest))
			return err
		}},
		{name: "findings", message: &v0sv1.FindingFilter{}, field: 1, call: func(m proto.Message) error {
			_, err := s.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{Filter: m.(*v0sv1.FindingFilter)})
			return err
		}},
		{name: "counts", message: &v0sv1.FindingFilter{}, field: 1, call: func(m proto.Message) error {
			_, err := s.CountFindings(t.Context(), &v0sv1.CountFindingsRequest{Filter: m.(*v0sv1.FindingFilter), GroupBy: v0sv1.CountFindingsRequest_GROUP_BY_SEVERITY})
			return err
		}},
		{name: "suppressions", message: &v0sv1.ListSuppressionsRequest{}, field: 1, call: func(m proto.Message) error {
			_, err := s.ListSuppressions(t.Context(), m.(*v0sv1.ListSuppressionsRequest))
			return err
		}},
		{name: "components", message: &v0sv1.SearchComponentsRequest{Query: "lodash"}, field: 2, call: func(m proto.Message) error {
			_, err := s.SearchComponents(t.Context(), m.(*v0sv1.SearchComponentsRequest))
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := protowire.AppendString(protowire.AppendTag(nil, tt.field, protowire.BytesType), "team")
			if err := proto.Unmarshal(wire, tt.message); err != nil {
				t.Fatal(err)
			}
			if err := tt.call(tt.message); status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "regenerate") {
				t.Errorf("old team filter: %v; want explicit client-upgrade error", err)
			}
		})
	}
}

func TestKnownExploited(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		want      bool
		wantError codes.Code
	}{
		{name: "not registered"},
		{name: "registered", sql: `UPDATE kev SET cve = 'CVE-1'`, want: true},
		{name: "catalog not loaded", sql: `DELETE FROM kev`, wantError: codes.Unavailable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newServer(t, tt.sql)
			ctx := t.Context()
			findings, err := s.ListFindings(ctx, &v0sv1.ListFindingsRequest{})
			if status.Code(err) != tt.wantError {
				t.Fatalf("list: %v; want %v", err, tt.wantError)
			}
			advisory, err := s.GetVulnerability(ctx, &v0sv1.GetVulnerabilityRequest{Id: "GHSA-1"})
			if status.Code(err) != tt.wantError {
				t.Fatalf("advisory: %v; want %v", err, tt.wantError)
			}
			counts, err := s.CountFindings(ctx, &v0sv1.CountFindingsRequest{
				Filter: &v0sv1.FindingFilter{OnlyKnownExploited: true}, GroupBy: v0sv1.CountFindingsRequest_GROUP_BY_SEVERITY,
			})
			if status.Code(err) != tt.wantError {
				t.Fatalf("KEV count: %v; want %v", err, tt.wantError)
			}
			if tt.wantError != codes.OK {
				if findings != nil || advisory != nil || counts != nil {
					t.Fatal("unavailable catalog returned data")
				}
				return
			}
			if len(findings.GetFindings()) != 4 {
				t.Fatalf("findings = %v; want all four workload occurrences", findings)
			}
			for _, finding := range findings.GetFindings() {
				if finding.GetKnownExploited() != tt.want {
					t.Errorf("finding membership = %v, want %v", finding.GetKnownExploited(), tt.want)
				}
			}
			if advisory.GetVulnerability().GetKnownExploited() != tt.want {
				t.Errorf("advisory membership = %v, want %v", advisory, tt.want)
			}
			var count int64
			for _, bucket := range counts.GetBuckets() {
				count += bucket.GetCount()
			}
			if tt.want && count != 4 || !tt.want && count != 0 {
				t.Errorf("KEV count = %d, want four if registered, zero otherwise", count)
			}
			filtered, err := s.ListFindings(ctx, &v0sv1.ListFindingsRequest{Filter: &v0sv1.FindingFilter{OnlyKnownExploited: true}})
			if err != nil || int64(len(filtered.GetFindings())) != count {
				t.Errorf("filtered findings = %v, %v; want %d", filtered, err, count)
			}
		})
	}
}

func TestVulnerabilityZeroEPSS(t *testing.T) {
	s := newServer(t, `
		INSERT INTO epss (cve, score, percentile, date) VALUES ('CVE-1', 0, 0, '2026-11-17');`)
	got, err := s.GetVulnerability(t.Context(), &v0sv1.GetVulnerabilityRequest{Id: "CVE-1"})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := proto.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(v0sv1.GetVulnerabilityResponse)
	if err := proto.Unmarshal(wire, decoded); err != nil {
		t.Fatal(err)
	}
	epss := decoded.GetVulnerability().GetEpss()
	if epss == nil || epss.GetScore() != 0 || epss.GetDate() != "2026-11-17" {
		t.Errorf("zero EPSS score was lost: %v", epss)
	}
}
