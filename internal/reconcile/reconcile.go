// Package reconcile runs the loops that move images from observed to scanned.
//
// Every loop is level-triggered: it reads what needs doing from Postgres, does it,
// and sleeps. Loops that write take a cluster-wide lock, so with several replicas
// one does the work and the others only serve the API.
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/nais/v0s/internal/attest"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/enrich"
	"github.com/nais/v0s/internal/v0s"
)

const (
	syncInterval   = time.Minute
	fetchInterval  = 10 * time.Second
	scanInterval   = 10 * time.Second
	dbInterval     = time.Hour
	enrichInterval = 24 * time.Hour
	fetchBatch     = 16
	fetchTimeout   = 2 * time.Minute
	retryMissing   = 6 * time.Hour
	retryFailed    = 30 * time.Minute
	retryLoop      = 5 * time.Minute
)

// Inventory reports the workload images in each environment.
type Inventory interface {
	// Snapshot returns the complete set of workload images of each environment it knows.
	Snapshot(ctx context.Context) (map[string][]v0s.WorkloadImage, error)
}

// Fetcher returns the verified SBOM for an image reference. Implementations must
// propagate context cancellation to registry requests to bound batch waiting.
type Fetcher interface {
	Fetch(ctx context.Context, ref string) ([]byte, error)
}

// Scanner matches SBOMs and keeps its vulnerability DB current. Scan returns the DB version it
// used, also with an error; the version is zero if no DB was loaded.
type Scanner interface {
	Update(ctx context.Context) (bool, error)
	DBVersion() time.Time
	Scan(ctx context.Context, sbom []byte) (v0s.ScanResult, time.Time, error)
}

// Reconciler runs the loops. All fields are required.
type Reconciler struct {
	DB        *database.DB
	Inventory Inventory
	Fetcher   Fetcher
	Scanner   Scanner
	HTTP      *http.Client
	Log       *slog.Logger
	Metrics   *Metrics
}

// Run runs every loop until ctx is done.
func (r *Reconciler) Run(ctx context.Context) {
	loops := []struct {
		name     string
		interval time.Duration
		fn       func(context.Context) error
	}{
		{"sync", syncInterval, r.sync},
		{"fetch", fetchInterval, r.fetch},
		{"scan", scanInterval, r.scan},
		{"vulndb", dbInterval, r.updateDB},
		{"enrich", enrichInterval, r.enrich},
	}
	var wg sync.WaitGroup
	for _, l := range loops {
		wg.Go(func() { every(ctx, l.interval, r.Log.With("loop", l.name), l.fn) })
	}
	wg.Wait()
}

// every runs fn now and then every interval until ctx is done. After a failure it
// retries sooner, so a daily job does not wait a day after a transient error.
func every(ctx context.Context, interval time.Duration, log *slog.Logger, fn func(context.Context) error) {
	for {
		wait := interval
		if err := fn(ctx); err != nil && ctx.Err() == nil {
			log.With("err", err).Error("loop failed")
			wait = min(interval, retryLoop)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// sync writes each environment's snapshot, then deletes the images no workload uses. Environments
// missing from the snapshot keep their stored workloads, as do all environments if the snapshot
// fails.
func (r *Reconciler) sync(ctx context.Context) error {
	return r.DB.WithLock(ctx, "sync", func(ctx context.Context) (err error) {
		defer func() {
			if ctx.Err() != nil {
				return
			}
			result := "error"
			if err == nil {
				result = "ok"
				r.Metrics.inventorySuccess.SetToCurrentTime()
			}
			r.Metrics.inventorySyncs.WithLabelValues(result).Inc()
		}()
		envs, err := r.Inventory.Snapshot(ctx)
		if err != nil {
			return fmt.Errorf("reading workloads: %w", err)
		}
		var errs []error
		for _, env := range slices.Sorted(maps.Keys(envs)) {
			if err := r.DB.SyncWorkloadImages(ctx, env, envs[env]); err != nil {
				errs = append(errs, err)
			}
		}
		n, err := r.DB.DeleteUnusedImages(ctx)
		if n > 0 {
			r.Log.With("count", n).Info("deleted unused images")
		}
		return errors.Join(append(errs, err)...)
	})
}

// fetch drains due SBOM fetches, fetching each batch concurrently.
func (r *Reconciler) fetch(ctx context.Context) error {
	return r.fetchDue(ctx, fetchTimeout)
}

func (r *Reconciler) fetchDue(ctx context.Context, timeout time.Duration) error {
	return r.DB.WithLock(ctx, "fetch", func(ctx context.Context) error {
		for ctx.Err() == nil {
			images, err := r.DB.DueSBOMFetches(ctx, fetchBatch)
			if err != nil || len(images) == 0 {
				return err
			}
			errs := make([]error, len(images))
			var wg sync.WaitGroup
			for i, img := range images {
				wg.Go(func() { errs[i] = r.fetchOne(ctx, img, timeout) })
			}
			wg.Wait()
			// An unrecorded fetch would be due again at once.
			if err := errors.Join(errs...); err != nil {
				return err
			}
		}
		return nil
	})
}

// fetchOne fetches the image's SBOM and records the outcome. It returns an error only if the
// outcome could not be recorded.
func (r *Reconciler) fetchOne(ctx context.Context, img v0s.Image, timeout time.Duration) error {
	// Bound the whole registry/verification attempt, including format fallback.
	// Persist a local timeout with the parent context so it gets normal backoff.
	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	doc, err := r.Fetcher.Fetch(fetchCtx, img.Ref())
	if fetchCtx.Err() != nil {
		err = fetchCtx.Err()
	}
	cancel()
	if ctx.Err() != nil {
		return nil // the image stays due
	}
	switch {
	case errors.Is(err, attest.ErrNotFound):
		r.Metrics.fetches.WithLabelValues("not_found").Inc()
		err = r.DB.RecordSBOMFailure(ctx, img.ID, v0s.SBOMMissing, err.Error(), time.Now().Add(retryMissing))
	case err != nil:
		r.Metrics.fetches.WithLabelValues("error").Inc()
		r.Log.With("image", img.Ref(), "err", err).Warn("fetching SBOM")
		err = r.DB.RecordSBOMFailure(ctx, img.ID, v0s.SBOMFailed, err.Error(), time.Now().Add(retryFailed))
	default:
		r.Metrics.fetches.WithLabelValues("found").Inc()
		err = r.DB.StoreSBOM(ctx, img.ID, doc)
	}
	if err != nil {
		return fmt.Errorf("recording SBOM fetch of %s: %w", img.Ref(), err)
	}
	return nil
}

// scan drains images not yet scanned with the loaded DB, one at a time.
func (r *Reconciler) scan(ctx context.Context) error {
	version := r.Scanner.DBVersion()
	if version.IsZero() {
		return nil
	}
	return r.DB.WithLock(ctx, "scan", func(ctx context.Context) error {
		for ctx.Err() == nil {
			job, ok, err := r.DB.NextScan(ctx, version)
			if err != nil || !ok {
				return err
			}
			if err := r.scanOne(ctx, job); err != nil {
				return err
			}
		}
		return nil
	})
}

// scanOne scans the job's SBOM and records the outcome. It returns an error if no outcome was
// recorded, since NextScan would hand out the same image again at once.
func (r *Reconciler) scanOne(ctx context.Context, j database.ScanJob) error {
	start := time.Now()
	res, version, err := r.Scanner.Scan(ctx, j.SBOM)
	if ctx.Err() != nil {
		return nil
	}
	r.Metrics.scanDuration.Observe(time.Since(start).Seconds())
	result := "ok"
	if err != nil {
		result = "error"
	}
	r.Metrics.scans.WithLabelValues(result).Inc()
	log := r.Log.With("image", j.Image.Ref(), "db_version", version)
	switch {
	case err != nil && version.IsZero():
		return fmt.Errorf("scanning %s without a vulnerability DB: %w", j.Image.Ref(), err)
	case err != nil:
		log.With("err", err).Warn("scanning")
		err = r.DB.RecordScanFailure(ctx, j.Image.ID, version, err.Error())
	default:
		err = r.DB.StoreScan(ctx, j.Image.ID, version, res)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && (strings.HasPrefix(pgErr.Code, "22") || strings.HasPrefix(pgErr.Code, "23")) {
			// The result itself is rejected (data exception or constraint violation), so
			// retrying with the same DB cannot help.
			log.With("err", err).Warn("storing scan")
			err = r.DB.RecordScanFailure(ctx, j.Image.ID, version, err.Error())
		}
	}
	if err != nil {
		return fmt.Errorf("recording scan of %s: %w", j.Image.Ref(), err)
	}
	return nil
}

func (r *Reconciler) updateDB(ctx context.Context) error {
	updated, err := r.Scanner.Update(ctx)
	switch {
	case err != nil:
		r.Metrics.dbUpdates.WithLabelValues("error").Inc()
	case updated:
		r.Metrics.dbUpdates.WithLabelValues("updated").Inc()
	default:
		r.Metrics.dbUpdates.WithLabelValues("unchanged").Inc()
	}
	return err
}

// enrich replaces the EPSS and KEV tables.
func (r *Reconciler) enrich(ctx context.Context) error {
	return r.DB.WithLock(ctx, "enrich", func(ctx context.Context) error {
		var errs []error
		epss, err := enrich.FetchEPSS(ctx, r.HTTP, enrich.DefaultEPSSURL)
		if err != nil {
			errs = append(errs, err)
		} else if err := r.DB.ReplaceEPSS(ctx, epss); err != nil {
			errs = append(errs, err)
		} else {
			r.Metrics.enrichmentSuccess.WithLabelValues("epss").SetToCurrentTime()
		}
		kev, err := enrich.FetchKEV(ctx, r.HTTP, enrich.DefaultKEVURL)
		if err != nil {
			errs = append(errs, err)
		} else if err := r.DB.ReplaceKEV(ctx, kev); err != nil {
			errs = append(errs, err)
		} else {
			r.Metrics.enrichmentSuccess.WithLabelValues("kev").SetToCurrentTime()
		}
		return errors.Join(errs...)
	})
}
