package scan_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	fixtures "github.com/aquasecurity/bolt-fixtures"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/scan"
)

var discard = slog.New(slog.DiscardHandler)

func TestScan(t *testing.T) {
	repo := newRegistry(t)
	version := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	pushDB(t, repo, version)

	s, err := scan.New(t.TempDir(), []string{repo}, discard)
	if err != nil {
		t.Fatal(err)
	}
	sbom, err := os.ReadFile("testdata/sbom.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Scan(t.Context(), sbom); !errors.Is(err, scan.ErrNoDB) {
		t.Fatalf("Scan before Update: err = %v, want ErrNoDB", err)
	}
	if swapped, err := s.Update(t.Context()); err != nil || !swapped {
		t.Fatalf("Update() = %v, %v, want true, nil", swapped, err)
	}

	const (
		musl   = "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=3.19.1"
		lodash = "pkg:npm/lodash@4.17.20"
	)
	want := v0s.ScanResult{
		Components: []v0s.Component{
			{PURL: musl, PackageKey: "pkg:apk/alpine/musl", Name: "musl", Version: "1.2.4-r2"},
			{PURL: lodash, PackageKey: "pkg:npm/lodash", Name: "lodash", Version: "4.17.20"},
		},
		Findings: []v0s.Finding{
			{VulnerabilityID: "CVE-2025-0001", PURL: musl, PackageKey: "pkg:apk/alpine/musl", InstalledVersion: "1.2.4-r2", FixedVersion: "1.2.4-r3", Status: "fixed", Severity: v0s.SeverityHigh, SeveritySource: "nvd", DataSource: "alpine"},
			{VulnerabilityID: "CVE-2025-0002", PURL: lodash, PackageKey: "pkg:npm/lodash", InstalledVersion: "4.17.20", FixedVersion: "4.17.21", Status: "fixed", Severity: v0s.SeverityMedium, SeveritySource: "ghsa", DataSource: "ghsa"},
			{VulnerabilityID: "GHSA-xxxx-yyyy-zzzz", PURL: lodash, PackageKey: "pkg:npm/lodash", InstalledVersion: "4.17.20", Status: "affected", Severity: v0s.SeverityLow, SeveritySource: "ghsa", DataSource: "ghsa"},
		},
		Vulnerabilities: []v0s.Vulnerability{
			{
				ID: "CVE-2025-0001", Title: "musl overflow", Description: "A buffer overflow in musl.",
				Severities:  map[string]v0s.Severity{"nvd": v0s.SeverityHigh},
				CVSS:        map[string]v0s.CVSS{"nvd": {V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", V3Score: 7.5}},
				References:  []string{"https://example.com/CVE-2025-0001"},
				PublishedAt: time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
				ModifiedAt:  time.Date(2025, 1, 3, 0, 0, 0, 0, time.UTC),
			},
			{
				ID: "CVE-2025-0002", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Title: "lodash prototype pollution",
				Severities: map[string]v0s.Severity{"ghsa": v0s.SeverityMedium, "nvd": v0s.SeverityCritical},
				CVSS:       map[string]v0s.CVSS{"ghsa": {V40Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N", V40Score: 6.9}},
			},
			{
				ID: "GHSA-xxxx-yyyy-zzzz", Title: "lodash ReDoS",
				Severities: map[string]v0s.Severity{"ghsa": v0s.SeverityLow},
				CVSS:       map[string]v0s.CVSS{},
			},
		},
	}

	tests := []struct {
		name    string
		sbom    []byte
		want    v0s.ScanResult
		wantErr bool
	}{
		{name: "alpine and npm packages", sbom: sbom, want: want},
		{name: "not CycloneDX", sbom: []byte(`{"spdxVersion": "SPDX-2.3"}`), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotVersion, err := s.Scan(t.Context(), tt.sbom)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Scan() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Scan() error: %v", err)
			}
			if !gotVersion.Equal(version) {
				t.Errorf("Scan() version = %v, want %v", gotVersion, version)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Scan() =\n%+v\nwant\n%+v", got, tt.want)
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	ctx := t.Context()
	repo := newRegistry(t)
	dir := t.TempDir()
	v1 := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	v2 := v1.Add(6 * time.Hour)
	sbom, err := os.ReadFile("testdata/sbom.cdx.json")
	if err != nil {
		t.Fatal(err)
	}

	s, err := scan.New(dir, []string{"127.0.0.1:1/unreachable/trivy-db:2", repo}, discard)
	if err != nil {
		t.Fatal(err)
	}
	pushDB(t, repo, v1)
	update(t, s, true, v1)  // first DB, after falling back from the unreachable repo
	update(t, s, false, v1) // unchanged digest

	// Scans running during a swap see either DB, never an error.
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, v, err := s.Scan(ctx, sbom); err != nil || (!v.Equal(v1) && !v.Equal(v2)) {
					t.Errorf("Scan during swap = %v, %v", v, err)
					return
				}
			}
		})
	}
	pushDB(t, repo, v2)
	update(t, s, true, v2)
	close(stop)
	wg.Wait()

	pushDB(t, repo, v1)
	update(t, s, false, v2) // an older DB is never swapped in

	// A new Scanner picks up the newest DB and leaves nothing else behind.
	s, err = scan.New(dir, nil, discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.DBVersion(); !got.Equal(v2) {
		t.Errorf("DBVersion() after restart = %v, want %v", got, v2)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 {
		t.Errorf("DB directory has %d entries (err %v), want 1", len(entries), err)
	}
}

func update(t *testing.T, s *scan.Scanner, wantSwapped bool, wantVersion time.Time) {
	t.Helper()
	swapped, err := s.Update(t.Context())
	if err != nil || swapped != wantSwapped {
		t.Fatalf("Update() = %v, %v, want %v, nil", swapped, err, wantSwapped)
	}
	if got := s.DBVersion(); !got.Equal(wantVersion) {
		t.Errorf("DBVersion() = %v, want %v", got, wantVersion)
	}
}

// newRegistry starts an in-process OCI registry and returns a trivy-db repository in it.
// Registry credentials come from an empty Docker config.
func newRegistry(t *testing.T) string {
	t.Helper()
	t.Setenv("DOCKER_CONFIG", t.TempDir()) // keep the developer's credential helpers out of it
	srv := httptest.NewServer(registry.New(registry.Logger(log.New(io.Discard, "", 0))))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://") + "/aquasecurity/trivy-db:2"
}

// pushDB builds a trivy-db from testdata/fixtures, the way Trivy's internal/dbtest does,
// and pushes it to repo as a trivy-db artifact.
func pushDB(t *testing.T, repo string, updatedAt time.Time) {
	t.Helper()
	dir := t.TempDir()
	files, err := filepath.Glob("testdata/fixtures/*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	loader, err := fixtures.New(filepath.Join(dir, "trivy.db"), files)
	if err != nil {
		t.Fatal(err)
	}
	if err := loader.Load(); err != nil {
		t.Fatal(err)
	}
	if err := loader.Close(); err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(map[string]any{"Version": 2, "UpdatedAt": updatedAt, "NextUpdate": updatedAt.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), meta, 0o644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.AddFS(os.DirFS(dir)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	layer := static.NewLayer(buf.Bytes(), "application/vnd.aquasec.trivy.db.layer.v1.tar+gzip")
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:       layer,
		Annotations: map[string]string{"org.opencontainers.image.title": "db.tar.gz"},
	})
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.ParseReference(repo)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.Write(ref, mutate.MediaType(img, types.OCIManifestSchema1)); err != nil {
		t.Fatal(err)
	}
}
