package grpcapi_test

import (
	"context"
	"net"
	"testing"
	"time"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/grpcapi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func serve(t *testing.T, s *grpcapi.Server) v0sv1.SuppressionServiceClient {
	t.Helper()
	srv := grpc.NewServer()
	s.Register(srv)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return v0sv1.NewSuppressionServiceClient(conn)
}

func forwardRequest() *v0sv1.ForwardV13SSuppressionRequest {
	return &v0sv1.ForwardV13SSuppressionRequest{
		ImageName:        "repo/app",
		Package:          "pkg:npm/lodash@4.17.20",
		VulnerabilityIds: []string{"CVE-1", "GHSA-1"},
		Assessment: &v0sv1.V13SAssessment{
			State:     v0sv1.SuppressionState_SUPPRESSION_STATE_NOT_AFFECTED,
			Detail:    "not reachable",
			UpdatedBy: "v13s-user",
			UpdatedAt: timestamppb.New(time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)),
		},
	}
}

func TestForwardV13sSuppressionDisabled(t *testing.T) {
	client := serve(t, newServer(t))
	_, err := client.ForwardV13SSuppression(context.Background(), forwardRequest())
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("err = %v, want FailedPrecondition while disabled", err)
	}
}

func TestForwardV13sSuppression(t *testing.T) {
	ctx := context.Background()
	client := serve(t, newServerWithV13sForwarding(t, true))

	resp, err := client.ForwardV13SSuppression(ctx, forwardRequest())
	if err != nil {
		t.Fatal(err)
	}
	if resp.GetOutcome() != v0sv1.ForwardOutcome_FORWARD_OUTCOME_APPLIED || resp.GetApplied() != 4 {
		t.Errorf("forward = %v, want 4 applied", resp)
	}
	listed, err := client.ListSuppressions(ctx, &v0sv1.ListSuppressionsRequest{Team: "team"})
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range listed.GetSuppressions() {
		if s.GetPackageKey() != "pkg:npm/lodash" || s.GetVulnerabilityId() != "CVE-1" || s.GetUpdatedBy() != "v13s-user" ||
			!s.GetUpdatedAt().AsTime().Equal(time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)) {
			t.Errorf("suppression = %v, want the forwarded assessment", s)
		}
	}
	if len(listed.GetSuppressions()) != 4 {
		t.Errorf("listed %d suppressions, want 4", len(listed.GetSuppressions()))
	}

	unknown := forwardRequest()
	unknown.VulnerabilityIds = []string{"CVE-404"}
	if resp, err := client.ForwardV13SSuppression(ctx, unknown); err != nil || resp.GetOutcome() != v0sv1.ForwardOutcome_FORWARD_OUTCOME_UNKNOWN_VULNERABILITY {
		t.Errorf("unknown = %v, %v; want UNKNOWN_VULNERABILITY", resp, err)
	}

	noTime := forwardRequest()
	noTime.Assessment.UpdatedAt = nil
	if _, err := client.ForwardV13SSuppression(ctx, noTime); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no update time: err = %v, want InvalidArgument", err)
	}
	noState := forwardRequest()
	noState.Assessment.State = v0sv1.SuppressionState_SUPPRESSION_STATE_UNSPECIFIED
	if _, err := client.ForwardV13SSuppression(ctx, noState); status.Code(err) != codes.InvalidArgument {
		t.Errorf("no state: err = %v, want InvalidArgument", err)
	}

	unsuppressed := forwardRequest()
	unsuppressed.Assessment = nil
	resp, err = client.ForwardV13SSuppression(ctx, unsuppressed)
	if err != nil || resp.GetRemoved() != 4 {
		t.Errorf("unsuppress = %v, %v; want 4 removed", resp, err)
	}
}
