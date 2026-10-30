// Package reconcile runs the loops that move images from observed to scanned.
//
// Every loop is level-triggered: it reads what needs doing from Postgres, does it,
// and sleeps. Replicas share the work through leased claims, so any number may run.
package reconcile

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/attest"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/enrich"
)

const (
	syncInterval    = 30 * time.Second
	fetchInterval   = 10 * time.Second
	scanInterval    = 10 * time.Second
	dbInterval      = time.Hour
	enrichInterval  = 24 * time.Hour
	gcInterval      = time.Hour
	fetchBatch      = 16
	lease           = 5 * time.Minute
	retryMissing    = 6 * time.Hour
	retryFailed     = 30 * time.Minute
	unusedRetention = 7 * 24 * time.Hour
	retryLoop       = 5 * time.Minute
)

// Snapshotter reports the workload images observed in each cluster.
type Snapshotter interface {
	Clusters() []string
	Snapshot(cluster string) ([]v0s.WorkloadImage, bool)
}

// Fetcher returns the verified SBOM for an image reference.
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
	DB      *database.DB
	Watcher Snapshotter
	Fetcher Fetcher
	Scanner Scanner
	HTTP    *http.Client
	Log     *slog.Logger
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
		{"gc", gcInterval, r.gc},
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
			log.Error("loop failed", "error", err)
			wait = min(interval, retryLoop)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// sync writes each synced cluster's snapshot. Unsynced clusters are skipped:
// an empty cache must not erase the cluster's workloads.
func (r *Reconciler) sync(ctx context.Context) error {
	var errs []error
	for _, c := range r.Watcher.Clusters() {
		ws, ok := r.Watcher.Snapshot(c)
		if !ok {
			continue
		}
		if err := r.DB.SyncWorkloadImages(ctx, c, ws); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// fetch drains due SBOM fetches, fetching each batch concurrently.
func (r *Reconciler) fetch(ctx context.Context) error {
	for ctx.Err() == nil {
		images, err := r.DB.ClaimSBOMFetches(ctx, fetchBatch, lease)
		if err != nil || len(images) == 0 {
			return err
		}
		var wg sync.WaitGroup
		for _, img := range images {
			wg.Go(func() { r.fetchOne(ctx, img) })
		}
		wg.Wait()
	}
	return nil
}

func (r *Reconciler) fetchOne(ctx context.Context, img v0s.Image) {
	log := r.Log.With("image", img.Ref())
	doc, err := r.Fetcher.Fetch(ctx, img.Ref())
	if ctx.Err() != nil {
		return // the lease expires and another attempt follows
	}
	switch {
	case errors.Is(err, attest.ErrNotFound):
		err = r.DB.RecordSBOMFailure(ctx, img.ID, v0s.SBOMMissing, err.Error(), time.Now().Add(retryMissing))
	case err != nil:
		log.Warn("fetching SBOM", "error", err)
		err = r.DB.RecordSBOMFailure(ctx, img.ID, v0s.SBOMFailed, err.Error(), time.Now().Add(retryFailed))
	default:
		err = r.DB.StoreSBOM(ctx, img.ID, doc)
	}
	if err != nil {
		log.Error("recording SBOM fetch", "error", err)
	}
}

// scan drains images not yet scanned with the loaded DB.
func (r *Reconciler) scan(ctx context.Context) error {
	version := r.Scanner.DBVersion()
	if version.IsZero() {
		return nil
	}
	// One claim at a time, so that no claimed job waits behind others while its lease runs out.
	for ctx.Err() == nil {
		job, ok, err := r.DB.ClaimScan(ctx, version, lease)
		if err != nil || !ok {
			return err
		}
		r.scanOne(ctx, job)
	}
	return nil
}

func (r *Reconciler) scanOne(ctx context.Context, j database.ScanJob) {
	log := r.Log.With("image", j.Image.Ref())
	res, version, err := r.Scanner.Scan(ctx, j.SBOM)
	if ctx.Err() != nil {
		return
	}
	switch {
	case err != nil && version.IsZero():
		log.Warn("scanning without a vulnerability DB", "error", err)
		return // the lease expires and another attempt follows
	case err != nil:
		log.Warn("scanning", "error", err, "db_version", version)
		err = r.DB.RecordScanFailure(ctx, j.Image.ID, version, err.Error())
	default:
		err = r.DB.StoreScan(ctx, j.Image.ID, version, res)
	}
	if err != nil {
		log.Error("recording scan", "error", err)
	}
}

func (r *Reconciler) updateDB(ctx context.Context) error {
	updated, err := r.Scanner.Update(ctx)
	if updated {
		r.Log.Info("vulnerability DB updated", "version", r.Scanner.DBVersion())
	}
	return err
}

// enrich replaces the EPSS and KEV tables. One replica does it at a time.
func (r *Reconciler) enrich(ctx context.Context) error {
	_, err := r.DB.WithLock(ctx, "enrich", func(ctx context.Context) error {
		epss, err := enrich.FetchEPSS(ctx, r.HTTP, enrich.DefaultEPSSURL)
		if err != nil {
			return err
		}
		if err := r.DB.ReplaceEPSS(ctx, epss); err != nil {
			return err
		}
		kev, err := enrich.FetchKEV(ctx, r.HTTP, enrich.DefaultKEVURL)
		if err != nil {
			return err
		}
		return r.DB.ReplaceKEV(ctx, kev)
	})
	return err
}

func (r *Reconciler) gc(ctx context.Context) error {
	_, err := r.DB.WithLock(ctx, "gc", func(ctx context.Context) error {
		n, err := r.DB.DeleteUnusedImages(ctx, unusedRetention)
		if n > 0 {
			r.Log.Info("deleted unused images", "count", n)
		}
		return err
	})
	return err
}
