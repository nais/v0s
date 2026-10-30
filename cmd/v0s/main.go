// Command v0s watches workloads, scans their attested SBOMs and serves the facts over gRPC.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/nais/v0s/internal/attest"
	"github.com/nais/v0s/internal/auth"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/grpcapi"
	"github.com/nais/v0s/internal/kube"
	"github.com/nais/v0s/internal/reconcile"
	"github.com/nais/v0s/internal/scan"
)

type config struct {
	listenAddr      string
	probeAddr       string
	databaseURL     string
	tenant          string
	clusters        []string
	selfCluster     string
	githubOrgs      []string
	authAudience    string
	serviceAccounts []string
	trivyDBDir      string
	trivyDBRepos    []string
}

func loadConfig() (config, error) {
	c := config{
		listenAddr:      env("LISTEN_ADDR", ":50051"),
		probeAddr:       env("PROBE_ADDR", ":8080"),
		databaseURL:     env("DATABASE_URL", ""),
		tenant:          env("TENANT", ""),
		clusters:        list(env("CLUSTERS", "")),
		selfCluster:     env("SELF_CLUSTER", ""),
		githubOrgs:      list(env("GITHUB_ORGANIZATIONS", "")),
		authAudience:    env("AUTH_AUDIENCE", ""),
		serviceAccounts: list(env("AUTHORIZED_SERVICE_ACCOUNTS", "")),
		trivyDBDir:      env("TRIVY_DB_DIR", "/var/cache/v0s/trivy-db"),
		trivyDBRepos:    list(env("TRIVY_DB_REPOSITORIES", "mirror.gcr.io/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2")),
	}
	var missing []string
	for name, v := range map[string]bool{
		"DATABASE_URL":                c.databaseURL != "",
		"CLUSTERS or SELF_CLUSTER":    len(c.clusters) > 0 || c.selfCluster != "",
		"TENANT":                      c.tenant != "" || len(c.clusters) == 0,
		"GITHUB_ORGANIZATIONS":        len(c.githubOrgs) > 0,
		"AUTH_AUDIENCE":               c.authAudience != "",
		"AUTHORIZED_SERVICE_ACCOUNTS": len(c.serviceAccounts) > 0,
	} {
		if !v {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return config{}, fmt.Errorf("missing configuration: %s", strings.Join(missing, ", "))
	}
	return c, nil
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func list(s string) []string {
	var out []string
	for v := range strings.SplitSeq(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)
	if err := run(log); err != nil {
		log.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := database.Open(ctx, cfg.databaseURL)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer db.Close()

	// slog.SetDefault above must run before any scan: Trivy logs through slog.Default.
	scanner, err := scan.New(cfg.trivyDBDir, cfg.trivyDBRepos, log)
	if err != nil {
		return fmt.Errorf("opening vulnerability DB: %w", err)
	}
	fetcher, err := attest.NewFetcher(cfg.githubOrgs, log)
	if err != nil {
		return fmt.Errorf("creating attestation fetcher: %w", err)
	}
	restConfigs, err := kube.ClusterConfigs(cfg.tenant, cfg.clusters, cfg.selfCluster)
	if err != nil {
		return fmt.Errorf("configuring clusters: %w", err)
	}
	watcher, err := kube.NewWatcher(restConfigs, log)
	if err != nil {
		return fmt.Errorf("creating watcher: %w", err)
	}

	lis, err := net.Listen("tcp", cfg.listenAddr)
	if err != nil {
		return err
	}
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	srv := newGRPCServer(db, reg, cfg.authAudience, cfg.serviceAccounts, log)
	probes := &http.Server{Addr: cfg.probeAddr, Handler: newProbeHandler(db, reg, log), ReadHeaderTimeout: 5 * time.Second}

	r := &reconcile.Reconciler{
		DB:      db,
		Watcher: watcher,
		Fetcher: fetcher,
		Scanner: scanner,
		HTTP:    &http.Client{Timeout: 2 * time.Minute},
		Log:     log,
		Metrics: reconcile.NewMetrics(reg, db, scanner),
	}

	errc := make(chan error, 4)
	go func() { errc <- watcher.Run(ctx) }()
	go func() { r.Run(ctx); errc <- nil }()
	go func() { errc <- srv.Serve(lis) }()
	go func() { errc <- probes.ListenAndServe() }()
	log.Info("started", "addr", cfg.listenAddr, "clusters", watcher.Clusters())

	// Stop on a signal or when any part exits, then wait for the rest.
	pending := 4
	select {
	case <-ctx.Done():
	case err = <-errc:
		pending--
		stop()
	}
	stopGRPC(srv, shutdownTimeout)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	_ = probes.Shutdown(shutdownCtx) // best effort: probes carry no state
	for range pending {
		if e := <-errc; err == nil && e != nil && !errors.Is(e, http.ErrServerClosed) {
			err = e
		}
	}
	return err
}

// newGRPCServer returns the authenticated API server, with reflection, recording request durations
// in reg.
func newGRPCServer(db *database.DB, reg prometheus.Registerer, audience string, serviceAccounts []string, log *slog.Logger) *grpc.Server {
	duration := promauto.With(reg).NewHistogramVec(prometheus.HistogramOpts{
		Name:    "v0s_grpc_request_duration_seconds",
		Help:    "Duration of unary gRPC requests by method and status code.",
		Buckets: prometheus.DefBuckets,
	}, []string{"method", "code"})
	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			durationInterceptor(duration), // first, so that rejected requests are measured too
			grpcapi.RecoveryInterceptor(log),
			auth.UnaryInterceptor(audience, serviceAccounts, log),
		),
		// Reflection is a streaming RPC: this keeps it behind the same authentication as the API.
		grpc.StreamInterceptor(auth.StreamInterceptor(audience, serviceAccounts, log)),
	)
	grpcapi.New(db, log).Register(srv)
	reflection.Register(srv)
	return srv
}

// durationInterceptor observes each request's duration in h, by method and status code.
func durationInterceptor(h *prometheus.HistogramVec) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		start := time.Now()
		resp, err := handler(ctx, req)
		h.WithLabelValues(info.FullMethod, status.Code(err).String()).Observe(time.Since(start).Seconds())
		return resp, err
	}
}

// newProbeHandler serves the probes and the metrics in reg. They are plain HTTP, outside the
// authenticated gRPC server.
func newProbeHandler(db *database.DB, reg *prometheus.Registry, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := db.Ping(r.Context()); err != nil {
			http.Error(w, "database unreachable", http.StatusServiceUnavailable)
		}
	})
	// A failing collector, such as v0s_images without a database, must not hide the other metrics.
	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
		ErrorLog:      slog.NewLogLogger(log.Handler(), slog.LevelError),
	}))
	return mux
}

// shutdownTimeout bounds each shutdown step.
const shutdownTimeout = 10 * time.Second

// stopGRPC stops srv gracefully, and cancels the RPCs still running after timeout.
func stopGRPC(srv *grpc.Server, timeout time.Duration) {
	stopped := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(timeout):
		srv.Stop()
		<-stopped
	}
}
