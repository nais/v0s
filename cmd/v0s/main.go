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

	"google.golang.org/grpc"

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
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(
		grpcapi.RecoveryInterceptor(log),
		auth.UnaryInterceptor(cfg.authAudience, cfg.serviceAccounts, log),
	))
	grpcapi.New(db, log).Register(srv)

	// Probes are plain HTTP, outside the authenticated gRPC server.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if err := db.Ping(r.Context()); err != nil {
			http.Error(w, "database unreachable", http.StatusServiceUnavailable)
		}
	})
	probes := &http.Server{Addr: cfg.probeAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}

	r := &reconcile.Reconciler{
		DB:      db,
		Watcher: watcher,
		Fetcher: fetcher,
		Scanner: scanner,
		HTTP:    &http.Client{Timeout: 2 * time.Minute},
		Log:     log,
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
