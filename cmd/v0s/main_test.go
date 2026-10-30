package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1"
	"google.golang.org/grpc/status"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/database/databasetest"
	"github.com/nais/v0s/internal/reconcile"
)

func TestMain(m *testing.M) { databasetest.Main(m) }

type fakeScanner struct{}

func (fakeScanner) Update(context.Context) (bool, error) { return false, nil }
func (fakeScanner) DBVersion() time.Time                 { return time.Time{} }
func (fakeScanner) Scan(context.Context, []byte) (v0s.ScanResult, time.Time, error) {
	return v0s.ScanResult{}, time.Time{}, nil
}

func TestProbeHandlerServesMetrics(t *testing.T) {
	db := databasetest.New(t)
	reg := prometheus.NewRegistry()
	reconcile.NewMetrics(reg, db, fakeScanner{})
	srv := httptest.NewServer(newProbeHandler(db, reg, slog.New(slog.NewTextHandler(io.Discard, nil))))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics: %s", resp.Status)
	}
	if !strings.Contains(string(body), "\nv0s_images{") {
		t.Errorf("GET /metrics has no v0s_images:\n%s", body)
	}
}

func TestReflectionRequiresAuthentication(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := newGRPCServer(nil, prometheus.NewRegistry(), "v0s", []string{"console@nais-io"}, log)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stream, err := reflectionpb.NewServerReflectionClient(conn).ServerReflectionInfo(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&reflectionpb.ServerReflectionRequest{
		MessageRequest: &reflectionpb.ServerReflectionRequest_ListServices{},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.Unauthenticated {
		t.Errorf("reflection without a token: %v, want Unauthenticated", err)
	}
}

func TestStopGRPCCancelsHangingRPC(t *testing.T) {
	started := make(chan struct{})
	srv := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		close(started)
		<-stream.Context().Done()
		return stream.Context().Err()
	}))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	go func() { _ = conn.Invoke(context.Background(), "/any.Service/Hang", nil, nil) }()
	<-started

	done := make(chan struct{})
	go func() {
		stopGRPC(srv, 100*time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("stopGRPC did not return with an RPC still running")
	}
}
