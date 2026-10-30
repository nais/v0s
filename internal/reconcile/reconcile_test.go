package reconcile

import (
	"context"
	"errors"
	"io"
	"log/slog"
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

type fakeWatcher map[string][]v0s.WorkloadImage // nil value: not synced

func (w fakeWatcher) Clusters() []string {
	var cs []string
	for c := range w {
		cs = append(cs, c)
	}
	return cs
}

func (w fakeWatcher) Snapshot(c string) ([]v0s.WorkloadImage, bool) { return w[c], w[c] != nil }

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
		return v0s.WorkloadImage{Cluster: "dev", Namespace: "team", Workload: app, Container: app, ImageName: "registry/" + app, Digest: digest}
	}
	prod := workload("stored", "sha256:e")
	prod.Cluster = "prod"
	if err := db.SyncWorkloadImages(ctx, "prod", []v0s.WorkloadImage{prod}); err != nil {
		t.Fatal(err)
	}
	r := &Reconciler{
		DB: db,
		Watcher: fakeWatcher{
			"dev":  {workload("scanned", "sha256:a"), workload("unsigned", "sha256:b"), workload("flaky", "sha256:c"), workload("garbage", "sha256:d")},
			"prod": nil, // not synced: its stored workloads must be kept
		},
		Fetcher: fakeFetcher{
			"registry/scanned@sha256:a": []byte("sbom"),
			"registry/flaky@sha256:c":   nil,
			"registry/garbage@sha256:d": []byte("garbage"),
		},
		Scanner: fakeScanner{version: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	images := map[string]v0s.Image{}
	clusters := map[string]string{}
	for _, w := range workloads {
		clusters[w.Name] = w.Cluster
		for _, c := range w.Containers {
			images[w.Name] = c.Image
		}
	}
	if got := clusters["stored"]; got != "prod" {
		t.Errorf("workload stored in unsynced cluster prod: cluster %q, want it kept", got)
	}
	wantState := map[string]v0s.SBOMState{"scanned": v0s.SBOMFetched, "unsigned": v0s.SBOMMissing, "flaky": v0s.SBOMFailed, "garbage": v0s.SBOMFetched}
	for app, want := range wantState {
		if got := images[app].SBOMState; got != want {
			t.Errorf("%s: SBOM state %q, want %q", app, got, want)
		}
	}
	if images["garbage"].ScanError == "" {
		t.Error("garbage: scan error not recorded")
	}

	findings, _, err := db.ListFindings(ctx, database.FindingFilter{}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Image.Name != "registry/scanned" || findings[0].Finding.VulnerabilityID != "CVE-2021-23337" {
		t.Errorf("findings = %+v, want CVE-2021-23337 in registry/scanned", findings)
	}

	// A second pass with the same DB version claims nothing.
	if _, ok, err := db.ClaimScan(ctx, r.Scanner.DBVersion(), time.Minute); err != nil || ok {
		t.Errorf("ClaimScan after pass = %t, %v; want nothing to claim", ok, err)
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
	w := v0s.WorkloadImage{Cluster: "dev", Namespace: "team", Workload: "app", Container: "app", ImageName: "registry/app", Digest: "sha256:a"}
	if err := db.SyncWorkloadImages(ctx, "dev", []v0s.WorkloadImage{w}); err != nil {
		t.Fatal(err)
	}
	r := &Reconciler{
		DB:      db,
		Watcher: fakeWatcher{},
		Fetcher: fakeFetcher{"registry/app@sha256:a": []byte("sbom")},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics: NewMetrics(prometheus.NewRegistry(), db, fakeScanner{}),
	}
	if err := r.fetch(ctx); err != nil {
		t.Fatal(err)
	}

	v1 := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	v2 := v1.Add(time.Hour)
	r.Scanner = staleScanner{fakeScanner: fakeScanner{version: v2}, used: v1}
	job, ok, err := db.ClaimScan(ctx, v2, time.Minute)
	if err != nil || !ok {
		t.Fatalf("ClaimScan = %t, %v, want a job", ok, err)
	}
	r.scanOne(ctx, job)

	if _, ok, err := db.ClaimScan(ctx, v2, time.Minute); err != nil || !ok {
		t.Errorf("ClaimScan for %v after a failure with %v = %t, %v; want the image again", v2, v1, ok, err)
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
// failure with that DB, so the image is not rescanned on every lease expiry.
func TestRejectedResultIsNotRetried(t *testing.T) {
	ctx := context.Background()
	db, url := databasetest.NewWithURL(t)
	w := v0s.WorkloadImage{Cluster: "dev", Namespace: "team", Workload: "app", Container: "app", ImageName: "registry/app", Digest: "sha256:a"}
	if err := db.SyncWorkloadImages(ctx, "dev", []v0s.WorkloadImage{w}); err != nil {
		t.Fatal(err)
	}
	version := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	r := &Reconciler{
		DB:      db,
		Watcher: fakeWatcher{},
		Fetcher: fakeFetcher{"registry/app@sha256:a": []byte("sbom")},
		Scanner: nulScanner{fakeScanner{version: version}},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics: NewMetrics(prometheus.NewRegistry(), db, fakeScanner{}),
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
