package grpcapi_test

import (
	"context"
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

func newServer(t *testing.T) *grpcapi.Server {
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
		INSERT INTO vulnerability_aliases (alias, vulnerability_id) VALUES ('GHSA-1', 'CVE-1');`)
	if err != nil {
		t.Fatal(err)
	}
	return grpcapi.New(db, slog.New(slog.DiscardHandler))
}

func TestSuppressions(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	key := &v0sv1.SuppressionKey{ImageName: "repo/app", Package: "pkg:npm/lodash@4.17.20", VulnerabilityId: "GHSA-1"}

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
	if got.GetTeam() != "team" || got.GetImageName() != "repo/app" || got.GetPackageKey() != "pkg:npm/lodash" || got.GetVulnerabilityId() != "CVE-1" ||
		got.GetState() != v0sv1.SuppressionState_SUPPRESSION_STATE_NOT_AFFECTED || got.GetDetail() != "never called" ||
		got.GetUpdatedBy() != "me" || got.GetUpdatedAt() == nil {
		t.Errorf("set suppression = %v", got)
	}

	deleted, err := s.DeleteSuppressions(ctx, &v0sv1.DeleteSuppressionsRequest{Team: "team", Keys: []*v0sv1.SuppressionKey{key}})
	if err != nil || len(deleted.GetDeleted()) != 1 {
		t.Errorf("DeleteSuppressions = %v, %v; want the suppression deleted", deleted.GetDeleted(), err)
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
