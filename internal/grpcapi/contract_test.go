package grpcapi_test

import (
	"strings"
	"testing"

	v0sv1 "github.com/nais/v0s-api/v0s/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

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

func TestVulnerabilityCVSSVersionsAndPresence(t *testing.T) {
	const (
		v30Zero = "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
		v31Zero = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"
		v31     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
		v40     = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
		v40Zero = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
	)
	s := newServer(t, `
		UPDATE vulnerabilities SET cvss = '{
			"alpine": {"v3_vector": "`+v30Zero+`"},
			"empty": {},
			"ghsa": {"v3_vector": "`+v31+`", "v3_score": 7.5, "v40_vector": "`+v40+`", "v40_score": 6.9},
			"invalid": {"v3_vector": "CVSS:3.1/broken"},
			"missing": {"v3_vector": "`+v31+`"},
			"nvd": {"v3_score": 8.1},
			"zero-v3": {"v3_vector": "`+v31Zero+`"},
			"zero-v4": {"v40_vector": "`+v40Zero+`"}
		}' WHERE id = 'CVE-1';
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
	want := []*v0sv1.Cvss{
		{Source: "alpine", Version: "3.0", Vector: proto.String(v30Zero), Score: proto.Float64(0)},
		{Source: "ghsa", Version: "3.1", Vector: proto.String(v31), Score: proto.Float64(7.5)},
		{Source: "ghsa", Version: "4.0", Vector: proto.String(v40), Score: proto.Float64(6.9)},
		{Source: "invalid", Version: "3.1", Vector: proto.String("CVSS:3.1/broken")},
		{Source: "missing", Version: "3.1", Vector: proto.String(v31)},
		{Source: "nvd", Version: "3.x", Score: proto.Float64(8.1)},
		{Source: "zero-v3", Version: "3.1", Vector: proto.String(v31Zero), Score: proto.Float64(0)},
		{Source: "zero-v4", Version: "4.0", Vector: proto.String(v40Zero), Score: proto.Float64(0)},
	}
	scores := decoded.GetVulnerability().GetCvss()
	if len(scores) != len(want) {
		t.Fatalf("CVSS = %v, want %v", scores, want)
	}
	for i := range want {
		if !proto.Equal(scores[i], want[i]) {
			t.Errorf("CVSS[%d] = %v, want %v", i, scores[i], want[i])
		}
	}
	epss := decoded.GetVulnerability().GetEpss()
	if epss == nil || epss.GetScore() != 0 || epss.GetDate() != "2026-11-17" {
		t.Errorf("zero EPSS score was lost: %v", epss)
	}
}
