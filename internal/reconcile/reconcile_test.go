package reconcile

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/attest"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
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
		return v0s.ScanResult{}, time.Time{}, errors.New("not an SBOM")
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
	r := &Reconciler{
		DB: db,
		Watcher: fakeWatcher{
			"dev":  {workload("scanned", "sha256:a"), workload("unsigned", "sha256:b"), workload("flaky", "sha256:c"), workload("garbage", "sha256:d")},
			"prod": nil, // not synced: must not be written
		},
		Fetcher: fakeFetcher{
			"registry/scanned@sha256:a": []byte("sbom"),
			"registry/flaky@sha256:c":   nil,
			"registry/garbage@sha256:d": []byte("garbage"),
		},
		Scanner: fakeScanner{version: time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)},
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
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
	for _, w := range workloads {
		if w.Cluster != "dev" {
			t.Errorf("workload %s/%s from unsynced cluster", w.Cluster, w.Name)
		}
		for _, c := range w.Containers {
			images[w.Name] = c.Image
		}
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
	jobs, err := db.ClaimScans(ctx, r.Scanner.DBVersion(), 10, time.Minute)
	if err != nil || len(jobs) != 0 {
		t.Errorf("ClaimScans after pass = %d jobs, %v; want none", len(jobs), err)
	}
}
