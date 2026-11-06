package reconcile

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/attest"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
	"github.com/prometheus/client_golang/prometheus"
)

func TestMain(m *testing.M) { databasetest.Main(m) }

var discard = slog.New(slog.DiscardHandler)

// fakeInventory is a snapshot; a nil inventory fails.
type fakeInventory map[string][]v0s.WorkloadImage

func (inv fakeInventory) Snapshot(context.Context) (map[string][]v0s.WorkloadImage, error) {
	if inv == nil {
		return nil, errors.New("Nais API unavailable")
	}
	return inv, nil
}

type fakeFetcher map[string][]byte // missing ref: not found; nil SBOM: transient error

func (f fakeFetcher) Fetch(_ context.Context, ref string) ([]byte, error) {
	doc, ok := f[ref]
	switch {
	case !ok:
		return nil, attest.ErrNotFound
	case doc == nil:
		return nil, errors.New("registry unavailable")
	}
	return doc, nil
}

type fakeScanner struct{ version time.Time }

func (s fakeScanner) Update(context.Context) (bool, error) { return false, nil }
func (s fakeScanner) DBVersion() time.Time                 { return s.version }
func (s fakeScanner) Scan(_ context.Context, sbom []byte) (v0s.ScanResult, time.Time, error) {
	if string(sbom) != "sbom" {
		return v0s.ScanResult{}, s.version, errors.New("not an SBOM")
	}
	return v0s.ScanResult{
		Components: []v0s.Component{{PURL: "pkg:npm/lodash@4.17.20", PackageKey: "pkg:npm/lodash", Name: "lodash", Version: "4.17.20"}},
		Findings: []v0s.Finding{{
			VulnerabilityID: "CVE-2021-23337", PURL: "pkg:npm/lodash@4.17.20", PackageKey: "pkg:npm/lodash",
			InstalledVersion: "4.17.20", FixedVersion: "4.17.21", Status: "fixed", Severity: v0s.SeverityHigh,
		}},
		Vulnerabilities: []v0s.Vulnerability{{ID: "CVE-2021-23337", Title: "Command injection in lodash"}},
	}, s.version, nil
}

// TestPipeline runs one pass of each loop and checks what reached the store.
func TestPipeline(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)

	workload := func(app, digest string) v0s.WorkloadImage {
		return v0s.WorkloadImage{Environment: "dev", Team: "team", Workload: app, ImageName: "registry/" + app, Digest: digest}
	}
	r := &Reconciler{
		DB: db,
		Inventory: fakeInventory{
			"dev": {
				workload("scanned", "sha256:a"), workload("unsigned", "sha256:b"), workload("flaky", "sha256:c"), workload("garbage", "sha256:d"),
				{Environment: "dev", Team: "team", Workload: "unresolved", Reference: "registry/unresolved:1", ResolveError: "tag not found"},
			},
		},
		Fetcher: fakeFetcher{
			"registry/scanned@sha256:a": []byte("sbom"),
			"registry/flaky@sha256:c":   nil,
			"registry/garbage@sha256:d": []byte("garbage"),
		},
		Scanner: fakeScanner{version: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)},
		Log:     discard,
		Metrics: NewMetrics(prometheus.NewRegistry(), db, fakeScanner{}),
	}
	for _, step := range []func(context.Context) error{r.sync, r.fetch, r.scan} {
		if err := step(ctx); err != nil {
			t.Fatal(err)
		}
	}

	workloads, _, err := db.ListWorkloads(ctx, database.WorkloadFilter{}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	status := map[string]v0s.ImageStatus{}
	for _, w := range workloads {
		if w.Image == nil {
			if w.ResolveError == "" {
				t.Errorf("%s: no image and no resolve error", w.Name)
			}
			status[w.Name] = "unresolved"
			continue
		}
		status[w.Name] = w.Image.Status()
	}
	want := map[string]v0s.ImageStatus{
		"scanned": v0s.ImageScanned, "unsigned": v0s.ImageNoSBOM, "flaky": v0s.ImageFailed, "garbage": v0s.ImageFailed,
		"unresolved": "unresolved",
	}
	if !maps.Equal(status, want) {
		t.Errorf("statuses = %v, want %v", status, want)
	}

	findings, _, err := db.ListFindings(ctx, database.FindingFilter{}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Image.Name != "registry/scanned" || findings[0].Finding.VulnerabilityID != "CVE-2021-23337" {
		t.Errorf("findings = %+v, want CVE-2021-23337 in registry/scanned", findings)
	}

	// A second pass with the same DB version finds nothing to scan.
	if _, ok, err := db.NextScan(ctx, r.Scanner.DBVersion()); err != nil || ok {
		t.Errorf("NextScan after pass = %t, %v; want nothing to scan", ok, err)
	}
}

// TestSyncDeletesUnusedImages checks that an image no workload uses anymore is deleted at once,
// while images of environments missing from the snapshot are kept.
func TestSyncDeletesUnusedImages(t *testing.T) {
	ctx := context.Background()
	db, url := databasetest.NewWithURL(t)
	workload := func(env, app string) v0s.WorkloadImage {
		return v0s.WorkloadImage{Environment: env, Team: "team", Workload: app, ImageName: "registry/" + app, Digest: "sha256:" + app}
	}
	if err := db.SyncWorkloadImages(ctx, "dev", []v0s.WorkloadImage{workload("dev", "kept"), workload("dev", "removed")}); err != nil {
		t.Fatal(err)
	}
	if err := db.SyncWorkloadImages(ctx, "prod", []v0s.WorkloadImage{workload("prod", "stored")}); err != nil {
		t.Fatal(err)
	}
	r := &Reconciler{
		DB:        db,
		Inventory: fakeInventory{"dev": {workload("dev", "kept")}},
		Log:       discard,
	}
	if err := r.sync(ctx); err != nil {
		t.Fatal(err)
	}

	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	rows, err := conn.Query(ctx, `SELECT name FROM images ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"registry/kept", "registry/stored"}; !slices.Equal(got, want) {
		t.Errorf("images = %q, want %q", got, want)
	}
}

// TestOneScanner checks that only the holder of the scan lock scans.
func TestOneScanner(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	w := v0s.WorkloadImage{Environment: "dev", Team: "team", Workload: "app", ImageName: "registry/app", Digest: "sha256:a"}
	if err := db.SyncWorkloadImages(ctx, "dev", []v0s.WorkloadImage{w}); err != nil {
		t.Fatal(err)
	}
	version := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	r := &Reconciler{
		DB:      db,
		Fetcher: fakeFetcher{"registry/app@sha256:a": []byte("sbom")},
		Scanner: fakeScanner{version: version},
		Log:     discard,
		Metrics: NewMetrics(prometheus.NewRegistry(), db, fakeScanner{}),
	}
	if err := r.fetch(ctx); err != nil {
		t.Fatal(err)
	}

	// Another replica holds the lock while this one tries to scan.
	if err := db.WithLock(ctx, "scan", r.scan); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := db.NextScan(ctx, version); err != nil || !ok {
		t.Errorf("NextScan after a scan without the lock = %t, %v; want the image still unscanned", ok, err)
	}
}

// TestFailedSnapshotKeepsWorkloads checks that an unavailable inventory is not taken to mean
// that nothing runs.
func TestFailedSnapshotKeepsWorkloads(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	w := v0s.WorkloadImage{Environment: "dev", Team: "team", Workload: "app", ImageName: "registry/app", Digest: "sha256:a"}
	if err := db.SyncWorkloadImages(ctx, "dev", []v0s.WorkloadImage{w}); err != nil {
		t.Fatal(err)
	}
	r := &Reconciler{DB: db, Inventory: fakeInventory(nil), Log: discard}
	if err := r.sync(ctx); err == nil {
		t.Error("sync with an unavailable inventory succeeded, want an error")
	}
	workloads, _, err := db.ListWorkloads(ctx, database.WorkloadFilter{}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(workloads) != 1 {
		t.Errorf("%d workloads after a failed snapshot, want the stored one kept", len(workloads))
	}
}

// staleScanner fails every scan with the DB version it had before an update.
type staleScanner struct {
	fakeScanner
	used time.Time
}

func (s staleScanner) Scan(context.Context, []byte) (v0s.ScanResult, time.Time, error) {
	return v0s.ScanResult{}, s.used, errors.New("scan failed")
}

// TestScanFailureRecordsUsedVersion checks that a scan failing with an older DB than the one
// loaded afterwards does not mark the image as attempted with the newer DB.
func TestScanFailureRecordsUsedVersion(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	w := v0s.WorkloadImage{Environment: "dev", Team: "team", Workload: "app", ImageName: "registry/app", Digest: "sha256:a"}
	if err := db.SyncWorkloadImages(ctx, "dev", []v0s.WorkloadImage{w}); err != nil {
		t.Fatal(err)
	}
	r := &Reconciler{
		DB:        db,
		Inventory: fakeInventory{},
		Fetcher:   fakeFetcher{"registry/app@sha256:a": []byte("sbom")},
		Log:       discard,
		Metrics:   NewMetrics(prometheus.NewRegistry(), db, fakeScanner{}),
	}
	if err := r.fetch(ctx); err != nil {
		t.Fatal(err)
	}

	v1 := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	v2 := v1.Add(time.Hour)
	r.Scanner = staleScanner{fakeScanner: fakeScanner{version: v2}, used: v1}
	job, ok, err := db.NextScan(ctx, v2)
	if err != nil || !ok {
		t.Fatalf("NextScan = %t, %v, want a job", ok, err)
	}
	if err := r.scanOne(ctx, job); err != nil {
		t.Fatal(err)
	}

	if _, ok, err := db.NextScan(ctx, v2); err != nil || !ok {
		t.Errorf("NextScan for %v after a failure with %v = %t, %v; want the image again", v2, v1, ok, err)
	}
}

// nulScanner returns a result Postgres rejects: text cannot contain NUL.
type nulScanner struct{ fakeScanner }

func (s nulScanner) Scan(context.Context, []byte) (v0s.ScanResult, time.Time, error) {
	return v0s.ScanResult{
		Components: []v0s.Component{{PURL: "pkg:npm/bad@1", PackageKey: "pkg:npm/bad", Name: "b\x00d", Version: "1"}},
	}, s.version, nil
}

// TestRejectedResultIsNotRetried checks that a result the database rejects is recorded as a
// failure with that DB, so the image is not rescanned on every pass.
func TestRejectedResultIsNotRetried(t *testing.T) {
	ctx := context.Background()
	db, url := databasetest.NewWithURL(t)
	w := v0s.WorkloadImage{Environment: "dev", Team: "team", Workload: "app", ImageName: "registry/app", Digest: "sha256:a"}
	if err := db.SyncWorkloadImages(ctx, "dev", []v0s.WorkloadImage{w}); err != nil {
		t.Fatal(err)
	}
	version := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	r := &Reconciler{
		DB:        db,
		Inventory: fakeInventory{},
		Fetcher:   fakeFetcher{"registry/app@sha256:a": []byte("sbom")},
		Scanner:   nulScanner{fakeScanner{version: version}},
		Log:       discard,
		Metrics:   NewMetrics(prometheus.NewRegistry(), db, fakeScanner{}),
	}
	if err := r.fetch(ctx); err != nil {
		t.Fatal(err)
	}
	if err := r.scan(ctx); err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var failed *time.Time
	if err := conn.QueryRow(ctx, `SELECT scan_failed_db_version FROM images`).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed == nil || !failed.Equal(version) {
		t.Errorf("scan_failed_db_version = %v, want %v", failed, version)
	}
}
