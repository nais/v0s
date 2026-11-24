package grpcapi_test

import (
	"strings"
	"testing"

	v0sv1 "github.com/nais/v0s/api/v0s/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestSuppressionEventsOverGRPC(t *testing.T) {
	s := newServer(t)
	writer, consumer := serve(t, s), serve(t, s)
	ctx := t.Context()
	key := &v0sv1.SuppressionKey{
		Environment: "prod", Workload: "app", ImageName: "repo/app",
		Package: "pkg:npm/lodash@1?arch=x", VulnerabilityId: "GHSA-1",
	}
	req := &v0sv1.SetSuppressionsRequest{
		Team: "team", Actor: "setter",
		Suppressions: []*v0sv1.NewSuppression{{Key: key, State: v0sv1.SuppressionState_SUPPRESSION_STATE_ACCEPTED_RISK, Detail: "assessed"}},
	}
	first, err := writer.SetSuppressions(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	req.Actor, req.Suppressions[0].Detail = "editor", "changed"
	second, err := writer.SetSuppressions(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	deleted, err := writer.DeleteSuppressions(ctx, &v0sv1.DeleteSuppressionsRequest{Team: "team", Keys: []*v0sv1.SuppressionKey{key}, Actor: "deleter"})
	if err != nil || len(deleted.GetDeleted()) != 1 {
		t.Fatalf("delete: %v, %v", deleted, err)
	}
	if _, err := writer.DeleteSuppressions(ctx, &v0sv1.DeleteSuppressionsRequest{Team: "team", Keys: []*v0sv1.SuppressionKey{key}, Actor: "retry"}); err != nil {
		t.Fatal(err)
	}
	batch, err := consumer.ListSuppressionEvents(ctx, &v0sv1.ListSuppressionEventsRequest{BatchSize: 2})
	if err != nil || len(batch.GetEvents()) != 2 {
		t.Fatalf("bounded batch: %v, %v", batch, err)
	}
	again, err := consumer.ListSuppressionEvents(ctx, &v0sv1.ListSuppressionEventsRequest{BatchSize: 2})
	if err != nil || !proto.Equal(again, batch) {
		t.Fatalf("unacknowledged redelivery changed: %v, %v", again, err)
	}
	created, updated := batch.Events[0], batch.Events[1]
	if created.EventId == "" || created.EventId == updated.EventId || created.Actor == nil || *created.Actor != "setter" ||
		created.Operation != v0sv1.SuppressionEventOperation_SUPPRESSION_EVENT_OPERATION_SET || created.Before != nil ||
		!proto.Equal(created.After, first.Suppressions[0]) || created.OccurredAt == nil || created.OccurredAt.CheckValid() != nil ||
		created.After.PackageKey != "pkg:npm/lodash" || created.After.VulnerabilityId != "CVE-1" ||
		updated.GetActor() != "editor" || !proto.Equal(updated.Before, first.Suppressions[0]) || !proto.Equal(updated.After, second.Suppressions[0]) {
		t.Fatalf("set events: %v", batch)
	}
	ack := &v0sv1.AcknowledgeSuppressionEventsRequest{EventIds: []string{created.EventId, updated.EventId, created.EventId}}
	for range 2 {
		if _, err := consumer.AcknowledgeSuppressionEvents(ctx, ack); err != nil {
			t.Fatal(err)
		}
	}
	last, err := consumer.ListSuppressionEvents(ctx, &v0sv1.ListSuppressionEventsRequest{})
	if err != nil || len(last.GetEvents()) != 1 {
		t.Fatalf("remaining delete event: %v, %v", last, err)
	}
	e := last.Events[0]
	if e.Operation != v0sv1.SuppressionEventOperation_SUPPRESSION_EVENT_OPERATION_DELETE || e.GetActor() != "deleter" ||
		!proto.Equal(e.Before, deleted.Deleted[0]) || e.After != nil {
		t.Fatalf("delete event: %v", e)
	}
	if _, err := consumer.AcknowledgeSuppressionEvents(ctx, &v0sv1.AcknowledgeSuppressionEventsRequest{EventIds: []string{e.EventId}}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.SetSuppressions(ctx, req); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.DeleteSuppressions(ctx, &v0sv1.DeleteSuppressionsRequest{Team: "team", Keys: []*v0sv1.SuppressionKey{key}}); err != nil {
		t.Fatal(err)
	}
	legacy, err := consumer.ListSuppressionEvents(ctx, &v0sv1.ListSuppressionEventsRequest{})
	if err != nil || len(legacy.GetEvents()) != 2 || legacy.Events[1].Actor != nil || legacy.Events[1].Before.UpdatedBy != "editor" {
		t.Fatalf("legacy deletion must retain unknown actor: %v, %v", legacy, err)
	}
	if _, err := consumer.AcknowledgeSuppressionEvents(ctx, &v0sv1.AcknowledgeSuppressionEventsRequest{
		EventIds: []string{legacy.Events[0].EventId, legacy.Events[1].EventId},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.ForwardV13SSuppression(ctx, forwardRequest()); err != nil {
		t.Fatal(err)
	}
	remove := forwardRequest()
	remove.Assessment = nil
	if _, err := writer.ForwardV13SSuppression(ctx, remove); err != nil {
		t.Fatal(err)
	}
	if pending, err := consumer.ListSuppressionEvents(ctx, &v0sv1.ListSuppressionEventsRequest{}); err != nil || len(pending.GetEvents()) != 0 {
		t.Fatalf("forwarding must not emit events: %v, %v", pending, err)
	}
}

func TestSuppressionEventValidationOverGRPC(t *testing.T) {
	client := serve(t, newServer(t))
	for _, size := range []int32{-1, 1001} {
		if _, err := client.ListSuppressionEvents(t.Context(), &v0sv1.ListSuppressionEventsRequest{BatchSize: size}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("batch size %d: %v", size, err)
		}
	}
	for _, ids := range [][]string{nil, {"bad"}, make([]string, 1001)} {
		if _, err := client.AcknowledgeSuppressionEvents(t.Context(), &v0sv1.AcknowledgeSuppressionEventsRequest{EventIds: ids}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("invalid ack: %v", err)
		}
	}
}

func TestSuppressionEventFailureOverGRPC(t *testing.T) {
	client := serve(t, newServer(t, `ALTER TABLE suppression_events ADD CHECK (after_value->>'workload' <> 'worker')`))
	items := make([]*v0sv1.NewSuppression, 0, 2)
	for _, workload := range []string{"app", "worker"} {
		items = append(items, &v0sv1.NewSuppression{
			Key:   &v0sv1.SuppressionKey{Environment: "prod", Workload: workload, ImageName: "repo/app", Package: "pkg:npm/lodash", VulnerabilityId: "CVE-1"},
			State: v0sv1.SuppressionState_SUPPRESSION_STATE_ACCEPTED_RISK, Detail: "assessed",
		})
	}

	if _, err := client.SetSuppressions(t.Context(), &v0sv1.SetSuppressionsRequest{Team: "team", Actor: "me", Suppressions: items}); status.Code(err) != codes.Internal {
		t.Fatalf("event storage failure must fail the write: %v", err)
	}
	stored, err := client.ListSuppressions(t.Context(), &v0sv1.ListSuppressionsRequest{})
	if err != nil || len(stored.GetSuppressions()) != 0 {
		t.Fatalf("batch partially committed: %v, %v", stored, err)
	}
	events, err := client.ListSuppressionEvents(t.Context(), &v0sv1.ListSuppressionEventsRequest{})
	if err != nil || len(events.GetEvents()) != 0 {
		t.Fatalf("batch partially enqueued: %v, %v", events, err)
	}
}

func TestSuppressionEventLargeSnapshotsOverGRPC(t *testing.T) {
	client := serve(t, newServer(t))
	req := &v0sv1.SetSuppressionsRequest{
		Team: "team", Actor: "me",
		Suppressions: []*v0sv1.NewSuppression{{
			Key:   &v0sv1.SuppressionKey{Environment: "prod", Workload: "app", ImageName: "repo/app", Package: "pkg:npm/lodash", VulnerabilityId: "CVE-1"},
			State: v0sv1.SuppressionState_SUPPRESSION_STATE_ACCEPTED_RISK, Detail: strings.Repeat("x", 3<<20),
		}},
	}
	for range 2 {
		if _, err := client.SetSuppressions(t.Context(), req); err != nil {
			t.Fatal(err)
		}
	}
	first, err := client.ListSuppressionEvents(t.Context(), &v0sv1.ListSuppressionEventsRequest{BatchSize: 1})
	if err != nil || len(first.GetEvents()) != 1 {
		t.Fatalf("creation event: %v", err)
	}
	if _, err := client.AcknowledgeSuppressionEvents(t.Context(), &v0sv1.AcknowledgeSuppressionEventsRequest{EventIds: []string{first.Events[0].EventId}}); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListSuppressionEvents(t.Context(), &v0sv1.ListSuppressionEventsRequest{BatchSize: 1}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("two snapshots must exceed the default receive limit: %v", err)
	}
	large, err := client.ListSuppressionEvents(t.Context(), &v0sv1.ListSuppressionEventsRequest{BatchSize: 1}, grpc.MaxCallRecvMsgSize(16<<20))
	if err != nil || len(large.GetEvents()) != 1 {
		t.Fatalf("event must remain deliverable after failed read: %v", err)
	}
	e := large.Events[0]
	if e.EventId == first.Events[0].EventId || len(e.GetBefore().GetDetail()) != 3<<20 || len(e.GetAfter().GetDetail()) != 3<<20 {
		t.Fatal("large before/after snapshots were lost or truncated")
	}
	if _, err := client.AcknowledgeSuppressionEvents(t.Context(), &v0sv1.AcknowledgeSuppressionEventsRequest{EventIds: []string{e.EventId}}); err != nil {
		t.Fatal(err)
	}
	if pending, err := client.ListSuppressionEvents(t.Context(), &v0sv1.ListSuppressionEventsRequest{}); err != nil || len(pending.GetEvents()) != 0 {
		t.Fatalf("acknowledged large event remains pending: %v", err)
	}
}
