package grpcapi_test

import (
	"context"
	"encoding/base64"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/database/databasetest"
	"github.com/nais/v0s/internal/grpcapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestMain(m *testing.M) { databasetest.Main(m) }

func newServer(t *testing.T, statements ...string) *grpcapi.Server {
	t.Helper()
	db, url := databasetest.NewWithURL(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, `
		INSERT INTO vulnerabilities (id, title, db_version) VALUES ('CVE-1', 'bug', now());
		INSERT INTO vulnerability_aliases (alias, vulnerability_id) VALUES ('GHSA-1', 'CVE-1');
		INSERT INTO images (name, digest) VALUES ('repo/app', 'sha256:a');
		INSERT INTO workloads (environment, team, name, image_reference, image_id)
		SELECT e, 'team', n, 'repo/app:1', id FROM images
		CROSS JOIN (VALUES ('prod'), ('dev')) environments(e)
		CROSS JOIN (VALUES ('app'), ('worker')) names(n);
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, status, severity)
		SELECT id, 'CVE-1', 'pkg:npm/lodash@4.17.20', 'pkg:npm/lodash', '4.17.20', 'affected', 'HIGH' FROM images;
		INSERT INTO kev (cve, date_added, known_ransomware_campaign) VALUES ('CVE-2', '2026-01-02', false);`)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range statements {
		if _, err := conn.Exec(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	return grpcapi.New(db, slog.New(slog.DiscardHandler))
}

func TestFindingVulnerabilityIDs(t *testing.T) {
	s := newServer(t, `
		INSERT INTO vulnerabilities (id, title, db_version) VALUES ('CVE-2', 'other bug', now());
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, status, severity)
		SELECT id, 'CVE-2', 'pkg:npm/express@4.0.0', 'pkg:npm/express', '4.0.0', 'affected', 'HIGH' FROM images;`)
	tests := []struct {
		name      string
		ids       []string
		want      int
		wantError codes.Code
	}{
		{name: "no filter", want: 8},
		{name: "one ID", ids: []string{"CVE-1"}, want: 4},
		{name: "multiple IDs and overlapping aliases", ids: []string{"CVE-1", "GHSA-1", "CVE-2", "CVE-404"}, want: 8},
		{name: "alias", ids: []string{"GHSA-1"}, want: 4},
		{name: "unknown ID", ids: []string{"CVE-404"}},
		{name: "empty ID", ids: []string{""}, wantError: codes.InvalidArgument},
		{name: "blank ID", ids: []string{"CVE-1", " "}, wantError: codes.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := &v0sv1.FindingFilter{VulnerabilityIds: tt.ids}
			findings, err := s.ListFindings(t.Context(), &v0sv1.ListFindingsRequest{Filter: filter})
			if status.Code(err) != tt.wantError {
				t.Fatalf("list: %v, want %v", err, tt.wantError)
			}
			counts, err := s.CountFindings(t.Context(), &v0sv1.CountFindingsRequest{
				Filter: filter, GroupBy: v0sv1.CountFindingsRequest_GROUP_BY_SEVERITY,
			})
			if status.Code(err) != tt.wantError {
				t.Fatalf("count: %v, want %v", err, tt.wantError)
			}
			if tt.wantError != codes.OK {
				return
			}
			if len(findings.GetFindings()) != tt.want {
				t.Errorf("findings = %d, want %d", len(findings.GetFindings()), tt.want)
			}
			var total int64
			for _, bucket := range counts.GetBuckets() {
				total += bucket.GetCount()
			}
			if total != int64(tt.want) {
				t.Errorf("count = %d, want %d", total, tt.want)
			}
		})
	}
}

func TestSuppressions(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	key := &v0sv1.SuppressionKey{Environment: "prod", Workload: "app", ImageName: "repo/app", Package: "pkg:npm/lodash@4.17.20", VulnerabilityId: "GHSA-1"}

	set, err := s.SetSuppressions(ctx, &v0sv1.SetSuppressionsRequest{
		Team:  "team",
		Actor: "me",
		Suppressions: []*v0sv1.NewSuppression{{
			Key:    key,
			State:  v0sv1.SuppressionState_SUPPRESSION_STATE_NOT_AFFECTED,
			Detail: "never called",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := set.GetSuppressions()[0]
	if got.GetTeam() != "team" || got.GetEnvironment() != "prod" || got.GetWorkload() != "app" ||
		got.GetImageName() != "repo/app" || got.GetPackageKey() != "pkg:npm/lodash" || got.GetVulnerabilityId() != "CVE-1" ||
		got.GetState() != v0sv1.SuppressionState_SUPPRESSION_STATE_NOT_AFFECTED || got.GetDetail() != "never called" ||
		got.GetUpdatedBy() != "me" || got.GetUpdatedAt() == nil {
		t.Errorf("set suppression = %v", got)
	}

	deleted, err := s.DeleteSuppressions(ctx, &v0sv1.DeleteSuppressionsRequest{Team: "team", Keys: []*v0sv1.SuppressionKey{key}})
	if err != nil || len(deleted.GetDeleted()) != 1 {
		t.Errorf("DeleteSuppressions = %v, %v; want the suppression deleted", deleted.GetDeleted(), err)
	}
}

func TestFindingCursorsSurviveSuppression(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	listed, err := s.ListFindings(ctx, &v0sv1.ListFindingsRequest{PageSize: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.GetFindings()) != 4 || len(listed.GetCursors()) != 4 || listed.GetNextPageToken() != "" {
		t.Fatalf("initial findings = %v, want four findings and their cursors on the last page", listed)
	}
	first := listed.GetFindings()[0]
	_, err = s.SetSuppressions(ctx, &v0sv1.SetSuppressionsRequest{
		Team: "team", Actor: "me",
		Suppressions: []*v0sv1.NewSuppression{{
			Key: &v0sv1.SuppressionKey{
				Environment: first.GetWorkload().GetEnvironment(), Workload: first.GetWorkload().GetName(),
				ImageName: first.GetImage().GetName(), Package: first.GetPackageKey(), VulnerabilityId: first.GetVulnerabilityId(),
			},
			State: v0sv1.SuppressionState_SUPPRESSION_STATE_ACCEPTED_RISK, Detail: "assessed",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i, cursor := range listed.GetCursors() {
		resumed, err := s.ListFindings(ctx, &v0sv1.ListFindingsRequest{PageSize: 10, PageToken: cursor})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := len(resumed.GetFindings()), 3-i; got != want {
			t.Fatalf("cursor %d returned %d findings after suppression, want %d", i, got, want)
		}
		if i < 3 {
			got, want := resumed.GetFindings()[0].GetWorkload(), listed.GetFindings()[i+1].GetWorkload()
			if got.GetEnvironment() != want.GetEnvironment() || got.GetName() != want.GetName() {
				t.Fatalf("cursor %d skipped the next workload: got %v, want %v", i, got, want)
			}
		}
	}
}

func TestSuppressionCursorsSurviveDeletion(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	keys := []*v0sv1.SuppressionKey{}
	items := []*v0sv1.NewSuppression{}
	for _, name := range []string{"app", "worker"} {
		key := &v0sv1.SuppressionKey{
			Environment: "prod", Workload: name, ImageName: "repo/app", Package: "pkg:npm/lodash", VulnerabilityId: "CVE-1",
		}
		keys = append(keys, key)
		items = append(items, &v0sv1.NewSuppression{
			Key: key, State: v0sv1.SuppressionState_SUPPRESSION_STATE_ACCEPTED_RISK, Detail: "assessed",
		})
	}
	if _, err := s.SetSuppressions(ctx, &v0sv1.SetSuppressionsRequest{Team: "team", Actor: "me", Suppressions: items}); err != nil {
		t.Fatal(err)
	}
	listed, err := s.ListSuppressions(ctx, &v0sv1.ListSuppressionsRequest{Team: "team"})
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.GetSuppressions()) != 2 || len(listed.GetCursors()) != 2 || listed.GetNextPageToken() != "" {
		t.Fatalf("initial suppressions = %v, want two suppressions and their cursors on the last page", listed)
	}
	if _, err := s.DeleteSuppressions(ctx, &v0sv1.DeleteSuppressionsRequest{Team: "team", Keys: keys[:1]}); err != nil {
		t.Fatal(err)
	}
	for i, cursor := range listed.GetCursors() {
		resumed, err := s.ListSuppressions(ctx, &v0sv1.ListSuppressionsRequest{Team: "team", PageToken: cursor})
		if err != nil {
			t.Fatal(err)
		}
		if got, want := len(resumed.GetSuppressions()), 1-i; got != want {
			t.Fatalf("cursor %d returned %d suppressions after deletion, want %d", i, got, want)
		}
		if i == 0 && resumed.GetSuppressions()[0].GetWorkload() != "worker" {
			t.Fatalf("next workload was skipped: %v", resumed)
		}
	}
}

func TestDiscoverAndBatchSuppressWorkloads(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	req := &v0sv1.ListFindingsRequest{
		Filter: &v0sv1.FindingFilter{
			Team: "team", VulnerabilityIds: []string{"GHSA-1"},
			Suppressed: v0sv1.SuppressedFilter_SUPPRESSED_FILTER_INCLUDE,
		},
		PageSize: 1,
	}
	var selected []*v0sv1.NewSuppression
	for {
		found, err := s.ListFindings(ctx, req)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range found.GetFindings() {
			if f.GetWorkload().GetEnvironment() != "prod" {
				continue
			}
			selected = append(selected, &v0sv1.NewSuppression{
				Key: &v0sv1.SuppressionKey{
					Environment: f.GetWorkload().GetEnvironment(), Workload: f.GetWorkload().GetName(),
					ImageName: f.GetImage().GetName(), Package: f.GetPackageKey(), VulnerabilityId: f.GetVulnerabilityId(),
				},
				State: v0sv1.SuppressionState_SUPPRESSION_STATE_ACCEPTED_RISK, Detail: "selected prod workloads",
			})
		}
		if found.GetNextPageToken() == "" {
			break
		}
		req.PageToken = found.GetNextPageToken()
	}
	if len(selected) != 2 {
		t.Fatalf("selected = %d, want both prod workloads", len(selected))
	}
	if _, err := s.SetSuppressions(ctx, &v0sv1.SetSuppressionsRequest{Team: "team", Actor: "me", Suppressions: selected}); err != nil {
		t.Fatal(err)
	}
	active, err := s.ListFindings(ctx, &v0sv1.ListFindingsRequest{Filter: &v0sv1.FindingFilter{Team: "team", VulnerabilityIds: []string{"CVE-1"}}})
	if err != nil || len(active.GetFindings()) != 2 {
		t.Fatalf("active findings = %v, %v; want both dev workloads", active, err)
	}
	for _, f := range active.GetFindings() {
		if f.GetWorkload().GetEnvironment() != "dev" {
			t.Errorf("unselected scope affected: %v", f)
		}
	}
	listed, err := s.ListSuppressions(ctx, &v0sv1.ListSuppressionsRequest{Team: "team", Environment: "prod", Workload: "worker"})
	if err != nil || len(listed.GetSuppressions()) != 1 || listed.GetSuppressions()[0].GetWorkload() != "worker" {
		t.Errorf("list worker = %v, %v", listed, err)
	}
	legacyKey := &v0sv1.SuppressionKey{ImageName: "repo/app", Package: "pkg:npm/lodash", VulnerabilityId: "CVE-1"}
	_, err = s.SetSuppressions(ctx, &v0sv1.SetSuppressionsRequest{Team: "team", Actor: "me", Suppressions: []*v0sv1.NewSuppression{{
		Key: legacyKey, State: v0sv1.SuppressionState_SUPPRESSION_STATE_ACCEPTED_RISK, Detail: "missing workload",
	}}})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("legacy write = %v, want InvalidArgument", err)
	}
	_, err = s.DeleteSuppressions(ctx, &v0sv1.DeleteSuppressionsRequest{Team: "team", Keys: []*v0sv1.SuppressionKey{legacyKey}})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("legacy delete = %v, want InvalidArgument", err)
	}
}

func TestErrorCodes(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
		want codes.Code
	}{
		{name: "count without group by", want: codes.InvalidArgument, call: func() error {
			_, err := s.CountFindings(ctx, &v0sv1.CountFindingsRequest{})
			return err
		}},
		{name: "unspecified severity", want: codes.InvalidArgument, call: func() error {
			_, err := s.ListFindings(ctx, &v0sv1.ListFindingsRequest{Filter: &v0sv1.FindingFilter{Severities: []v0sv1.Severity{0}}})
			return err
		}},
		{name: "invalid in the database", want: codes.InvalidArgument, call: func() error {
			_, err := s.ListSuppressions(ctx, &v0sv1.ListSuppressionsRequest{PageToken: "%%%"})
			return err
		}},
		{name: "old suppression cursor", want: codes.InvalidArgument, call: func() error {
			token := base64.RawURLEncoding.EncodeToString([]byte(`{"t":"team","i":"repo/app","p":"pkg:npm/lodash","v":"CVE-1"}`))
			_, err := s.ListSuppressions(ctx, &v0sv1.ListSuppressionsRequest{PageToken: token})
			return err
		}},
		{name: "not found", want: codes.NotFound, call: func() error {
			_, err := s.GetVulnerability(ctx, &v0sv1.GetVulnerabilityRequest{Id: "CVE-404"})
			return err
		}},
		{name: "canceled", want: codes.Canceled, call: func() error {
			ctx, cancel := context.WithCancel(ctx)
			cancel()
			_, err := s.ListFindings(ctx, &v0sv1.ListFindingsRequest{})
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.call(); status.Code(err) != tt.want {
				t.Errorf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestRecoveryInterceptor(t *testing.T) {
	intercept := grpcapi.RecoveryInterceptor(slog.New(slog.DiscardHandler))
	handler := func(context.Context, any) (any, error) { panic("boom") }
	_, err := intercept(context.Background(), nil, &grpc.UnaryServerInfo{FullMethod: "/v0s.v1.VulnerabilityService/ListFindings"}, handler)
	if status.Code(err) != codes.Internal {
		t.Errorf("err = %v, want Internal", err)
	}
}
