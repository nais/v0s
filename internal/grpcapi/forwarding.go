package grpcapi

import (
	"context"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"github.com/nais/v0s/internal/database"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) ForwardV13SSuppression(ctx context.Context, req *v0sv1.ForwardV13SSuppressionRequest) (*v0sv1.ForwardV13SSuppressionResponse, error) {
	if !s.v13sForwarding {
		return nil, status.Error(codes.FailedPrecondition, "forwarding from v13s is not enabled")
	}
	suppression := database.V13sSuppression{
		ImageName:        req.GetImageName(),
		Package:          req.GetPackage(),
		VulnerabilityIDs: req.GetVulnerabilityIds(),
	}
	if a := req.GetAssessment(); a != nil {
		if err := a.GetUpdatedAt().CheckValid(); err != nil {
			return nil, invalidArgument("assessment update time is required and must be valid")
		}
		suppression.Assessment = &database.V13sAssessment{
			State:     stateToDatabase(a.GetState()),
			Detail:    a.GetDetail(),
			UpdatedBy: a.GetUpdatedBy(),
			UpdatedAt: a.GetUpdatedAt().AsTime(),
		}
	}
	result, err := s.db.ApplyV13sSuppression(ctx, suppression)
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	return &v0sv1.ForwardV13SSuppressionResponse{
		Outcome: forwardOutcomeToProto(result.Outcome),
		Applied: int32(result.Applied),
		Removed: int32(result.Removed),
	}, nil
}

func forwardOutcomeToProto(o database.ForwardOutcome) v0sv1.ForwardOutcome {
	switch o {
	case database.ForwardApplied:
		return v0sv1.ForwardOutcome_FORWARD_OUTCOME_APPLIED
	case database.ForwardNoWorkloads:
		return v0sv1.ForwardOutcome_FORWARD_OUTCOME_NO_WORKLOADS
	case database.ForwardUnknownVulnerability:
		return v0sv1.ForwardOutcome_FORWARD_OUTCOME_UNKNOWN_VULNERABILITY
	case database.ForwardAmbiguousVulnerability:
		return v0sv1.ForwardOutcome_FORWARD_OUTCOME_AMBIGUOUS_VULNERABILITY
	}
	return v0sv1.ForwardOutcome_FORWARD_OUTCOME_UNSPECIFIED
}
