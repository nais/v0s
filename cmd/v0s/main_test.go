package main

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	reflectionpb "google.golang.org/grpc/reflection/grpc_reflection_v1"

	"github.com/nais/v0s/internal/database/databasetest"
	"github.com/nais/v0s/internal/reconcile"
	"github.com/nais/v0s/internal/v0s"
)

func TestMain(m *testing.M) { databasetest.Main(m) }

func TestMigrateCommandNeedsOnlyDatabaseConfiguration(t *testing.T) {
	_, url := databasetest.NewWithURL(t)
	t.Setenv("DATABASE_URL", url)
	t.Setenv("NAIS_API_GRPC_ADDRESS", "")
	t.Setenv("GITHUB_ORGANIZATIONS", "")
	if err := run(t.Context(), slog.New(slog.DiscardHandler), []string{"migrate"}); err != nil {
		t.Fatal(err)
	}
}

func TestCommandRejectsInvalidConfiguration(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	for _, args := range [][]string{{"migrate"}, {"unknown"}, {"migrate", "extra"}} {
		if err := run(t.Context(), slog.New(slog.DiscardHandler), args); err == nil {
			t.Errorf("run(%v) unexpectedly succeeded", args)
		}
	}
}

func TestAttestationIdentityConfiguration(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://localhost/v0s")
	t.Setenv("NAIS_API_GRPC_ADDRESS", "nais-api:3001")
	t.Setenv("GITHUB_ORGANIZATIONS", "nais")
	for _, tc := range []struct {
		value string
		want  int
		valid bool
	}{
		{"", 0, true},
		{"[]", 0, true},
		{`[{"issuer":"https://accounts.google.com","subjectRegExp":"[a-zA-Z0-9._%+-]+@nav\\.no","repositories":["ghcr.io/navikt"]}]`, 1, true},
		{`[{"issuer":"https://accounts.google.com","subjectRegExp":".+"}]`, 0, false},
		{"not JSON", 0, false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			t.Setenv("ATTESTATION_IDENTITY_RULES", tc.value)
			cfg, err := loadConfig()
			if (err == nil) != tc.valid {
				t.Fatalf("loadConfig: %v, valid=%v", err, tc.valid)
			}
			if len(cfg.identityRules) != tc.want {
				t.Fatalf("rules=%v, want count %d", cfg.identityRules, tc.want)
			}
		})
	}
}

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
	srv := httptest.NewServer(newProbeHandler(db, reg, slog.New(slog.DiscardHandler)))
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

func TestReflectionListsServices(t *testing.T) {
	log := slog.New(slog.DiscardHandler)
	srv := newGRPCServer(nil, prometheus.NewRegistry(), log)
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
	resp, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, s := range resp.GetListServicesResponse().GetService() {
		got = append(got, s.GetName())
	}
	for _, want := range []string{"v0s.v1.VulnerabilityService", "v0s.v1.SuppressionService"} {
		if !slices.Contains(got, want) {
			t.Errorf("services = %q, want %s among them", got, want)
		}
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
