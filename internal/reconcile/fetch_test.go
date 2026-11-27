package reconcile

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s/internal/attest"
	"github.com/nais/v0s/internal/database/databasetest"
	"github.com/nais/v0s/internal/v0s"
	"github.com/prometheus/client_golang/prometheus"
)

type fetcherFunc func(context.Context, string) ([]byte, error)

func (f fetcherFunc) Fetch(ctx context.Context, ref string) ([]byte, error) { return f(ctx, ref) }

func TestFetchTimeoutAllowsLaterBatches(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	db, url := databasetest.NewWithURL(t)
	const count = fetchBatch*2 + 1
	var workloads []v0s.WorkloadImage
	for n := range count {
		workloads = append(workloads, v0s.WorkloadImage{
			Environment: "dev", Team: "team", Workload: fmt.Sprintf("app-%02d", n),
			ImageName: fmt.Sprintf("registry/app-%02d", n), Digest: "sha256:a",
		})
	}
	if err := db.SyncWorkloadImages(ctx, "dev", workloads); err != nil {
		t.Fatal(err)
	}
	images, err := db.DueSBOMFetches(ctx, 1)
	if err != nil || len(images) != 1 {
		t.Fatalf("first due image: %v, %v", images, err)
	}
	slow := images[0]
	var calls atomic.Int64
	r := &Reconciler{
		DB: db, Log: discard, Metrics: NewMetrics(prometheus.NewRegistry(), db, fakeScanner{}),
		Fetcher: fetcherFunc(func(ctx context.Context, ref string) ([]byte, error) {
			calls.Add(1)
			if ref == slow.Ref() {
				<-ctx.Done()
				// Even a misleading not-found from a canceled verification must
				// be treated as timeout, not a missing attestation.
				return nil, attest.ErrNotFound
			}
			return []byte("sbom"), nil
		}),
	}
	start := time.Now()
	if err := r.fetchDue(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	end := time.Now()
	if got := calls.Load(); got != count {
		t.Fatalf("fetches = %d, want all %d across multiple batches", got, count)
	}

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var state, message string
	var retryAt time.Time
	if err := conn.QueryRow(ctx, `SELECT sbom_state, error, sbom_next_attempt_at FROM images WHERE id = $1`, slow.ID).Scan(&state, &message, &retryAt); err != nil {
		t.Fatal(err)
	}
	if state != string(v0s.SBOMFailed) || !strings.Contains(message, context.DeadlineExceeded.Error()) {
		t.Errorf("timed-out image: state=%s, error=%q; want failed with deadline exceeded", state, message)
	}
	if retryAt.Before(start.Add(retryFailed)) || retryAt.After(end.Add(retryFailed)) {
		t.Errorf("retry at %s, want 30 minutes after failure", retryAt)
	}
	var fetched int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM images WHERE sbom_state = 'fetched'`).Scan(&fetched); err != nil {
		t.Fatal(err)
	}
	if fetched != count-1 {
		t.Errorf("fetched = %d, want %d including later batches", fetched, count-1)
	}
	// The timed-out image must not spin as immediately due.
	if err := r.fetchDue(ctx, time.Second); err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != count {
		t.Errorf("fetches after another pass = %d, want still %d", got, count)
	}
}

func TestFetchCancellationLeavesImageDue(t *testing.T) {
	db := databasetest.New(t)
	if err := db.SyncWorkloadImages(t.Context(), "dev", []v0s.WorkloadImage{{
		Environment: "dev", Team: "team", Workload: "app", ImageName: "registry/app", Digest: "sha256:a",
	}}); err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	r := &Reconciler{
		DB: db, Log: discard, Metrics: NewMetrics(prometheus.NewRegistry(), db, fakeScanner{}),
		Fetcher: fetcherFunc(func(ctx context.Context, _ string) ([]byte, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		}),
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.fetchDue(ctx, time.Hour) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("fetch did not start")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fetch did not stop after parent cancellation")
	}
	images, err := db.DueSBOMFetches(t.Context(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != 1 || images[0].SBOMState != v0s.SBOMPending || images[0].Error != "" {
		t.Errorf("after shutdown: images=%+v, want the unchanged pending image still due", images)
	}
	// Cancellation must also release the cluster lock.
	locked := false
	if err := db.WithLock(t.Context(), "fetch", func(context.Context) error {
		locked = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Error("fetch lock remained held after shutdown")
	}
}

func TestFetchFailureRetryPolicy(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		state v0s.SBOMState
		retry time.Duration
		msg   string
	}{
		{
			"missing", fmt.Errorf("%w: got subjects [ola.nordmann@nav.no]", attest.ErrNotFound),
			v0s.SBOMMissing, 30 * time.Minute, missingMessage,
		},
		{"transport", errors.New("registry unavailable"), v0s.SBOMFailed, retryFailed, "registry unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, url := databasetest.NewWithURL(t)
			ctx := t.Context()
			if err := db.SyncWorkloadImages(ctx, "dev", []v0s.WorkloadImage{{
				Environment: "dev", Team: "team", Workload: "app", ImageName: "registry/app", Digest: "sha256:a",
			}}); err != nil {
				t.Fatal(err)
			}
			r := &Reconciler{
				DB: db, Log: discard, Metrics: NewMetrics(prometheus.NewRegistry(), db, fakeScanner{}),
				Fetcher: fetcherFunc(func(context.Context, string) ([]byte, error) { return nil, tc.err }),
			}
			start := time.Now()
			if err := r.fetch(ctx); err != nil {
				t.Fatal(err)
			}
			end := time.Now()
			conn, err := pgx.Connect(ctx, url)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close(ctx)
			var state, msg string
			var retryAt time.Time
			if err := conn.QueryRow(ctx, `SELECT sbom_state, error, sbom_next_attempt_at FROM images`).Scan(&state, &msg, &retryAt); err != nil {
				t.Fatal(err)
			}
			if state != string(tc.state) || retryAt.Before(start.Add(tc.retry)) || retryAt.After(end.Add(tc.retry)) {
				t.Errorf("state=%s, retry=%s; want %s and retry after %s", state, retryAt, tc.state, tc.retry)
			}
			if msg != tc.msg {
				t.Errorf("error = %q, want %q", msg, tc.msg)
			}
			due, err := db.DueSBOMFetches(ctx, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(due) != 0 {
				t.Fatalf("images due immediately after failure: %v", due)
			}
		})
	}
}
