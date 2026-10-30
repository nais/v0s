package grpcapi_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jackc/pgx/v5"
	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/database/databasetest"
	"github.com/nais/v0s/internal/grpcapi"
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
		INSERT INTO vulnerabilities (id, title) VALUES ('CVE-1', 'bug');
		INSERT INTO vulnerability_aliases (alias, vulnerability_id) VALUES ('GHSA-1', 'CVE-1');`)
	if err != nil {
		t.Fatal(err)
	}
	return grpcapi.New(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestSuppressionLifecycle(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()

	created, err := s.CreateSuppressions(ctx, &v0sv1.CreateSuppressionsRequest{
		Actor: "me",
		Suppressions: []*v0sv1.NewSuppression{{
			ImageName:       "repo/app",
			Package:         "pkg:npm/lodash@4.17.20",
			VulnerabilityId: "GHSA-1",
			State:           v0sv1.SuppressionState_SUPPRESSION_STATE_NOT_AFFECTED,
			Justification:   v0sv1.Justification_JUSTIFICATION_CODE_NOT_REACHABLE,
			Detail:          "never called",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := created.GetResults()[0].GetSuppression()
	if got.GetVulnerabilityId() != "CVE-1" || got.GetState() != v0sv1.SuppressionState_SUPPRESSION_STATE_NOT_AFFECTED ||
		got.GetJustification() != v0sv1.Justification_JUSTIFICATION_CODE_NOT_REACHABLE || got.GetCreatedAt() == nil {
		t.Errorf("created suppression = %v", got)
	}

	if _, err := s.RevokeSuppressions(ctx, &v0sv1.RevokeSuppressionsRequest{Ids: []int64{got.GetId()}, Actor: "me", Reason: "fixed"}); err != nil {
		t.Fatal(err)
	}
	_, err = s.RevokeSuppressions(ctx, &v0sv1.RevokeSuppressionsRequest{Ids: []int64{got.GetId()}, Actor: "me", Reason: "fixed"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("revoking twice: err = %v, want FailedPrecondition", err)
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
		{name: "malformed page token", want: codes.InvalidArgument, call: func() error {
			_, err := s.ListSuppressions(ctx, &v0sv1.ListSuppressionsRequest{PageToken: "%%%"})
			return err
		}},
		{name: "unknown vulnerability in suppression", want: codes.InvalidArgument, call: func() error {
			_, err := s.CreateSuppressions(ctx, &v0sv1.CreateSuppressionsRequest{Actor: "me", Suppressions: []*v0sv1.NewSuppression{{
				ImageName: "repo/app", Package: "pkg:npm/x", VulnerabilityId: "CVE-404",
				State: v0sv1.SuppressionState_SUPPRESSION_STATE_FALSE_POSITIVE, Detail: "d",
			}}})
			return err
		}},
		{name: "unknown vulnerability", want: codes.NotFound, call: func() error {
			_, err := s.GetVulnerability(ctx, &v0sv1.GetVulnerabilityRequest{Id: "CVE-404"})
			return err
		}},
		{name: "vulnerability by alias", want: codes.OK, call: func() error {
			_, err := s.GetVulnerability(ctx, &v0sv1.GetVulnerabilityRequest{Id: "GHSA-1"})
			return err
		}},
		{name: "revoke unknown", want: codes.NotFound, call: func() error {
			_, err := s.RevokeSuppressions(ctx, &v0sv1.RevokeSuppressionsRequest{Ids: []int64{404}, Actor: "me", Reason: "r"})
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
