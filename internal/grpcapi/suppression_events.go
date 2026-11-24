package grpcapi

import (
	"context"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
)

func (s *Server) ListSuppressionEvents(ctx context.Context, req *v0sv1.ListSuppressionEventsRequest) (*v0sv1.ListSuppressionEventsResponse, error) {
	events, err := s.db.ListSuppressionEvents(ctx, int(req.GetBatchSize()))
	if err != nil {
		return nil, s.toStatus(ctx, err)
	}
	resp := &v0sv1.ListSuppressionEventsResponse{Events: make([]*v0sv1.SuppressionEvent, 0, len(events))}
	for _, e := range events {
		operation := v0sv1.SuppressionEventOperation_SUPPRESSION_EVENT_OPERATION_SET
		if e.Operation == "delete" {
			operation = v0sv1.SuppressionEventOperation_SUPPRESSION_EVENT_OPERATION_DELETE
		}
		event := &v0sv1.SuppressionEvent{
			EventId: e.ID, Operation: operation, Actor: e.Actor, OccurredAt: timestamp(e.OccurredAt),
		}
		if e.Before != nil {
			event.Before = suppressionToProto(*e.Before)
		}
		if e.After != nil {
			event.After = suppressionToProto(*e.After)
		}
		resp.Events = append(resp.Events, event)
	}
	return resp, nil
}

func (s *Server) AcknowledgeSuppressionEvents(ctx context.Context, req *v0sv1.AcknowledgeSuppressionEventsRequest) (*v0sv1.AcknowledgeSuppressionEventsResponse, error) {
	if err := s.db.AcknowledgeSuppressionEvents(ctx, req.GetEventIds()); err != nil {
		return nil, s.toStatus(ctx, err)
	}
	return &v0sv1.AcknowledgeSuppressionEventsResponse{}, nil
}
