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

	"github.com/nais/v0s/internal/scan"
	"github.com/nais/v0s/internal/v0s"
)

var discard = slog.New(slog.DiscardHandler)

func TestMain(m *testing.M) {
	slog.SetDefault(discard) // see scan.New
	os.Exit(m.Run())
}

func TestScan(t *testing.T) {
	repo := newRegistry(t)
	version := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	pushDB(t, repo, version)

	s, err := scan.New(t.TempDir(), []string{repo}, discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, v, err := s.Scan(t.Context(), readFile(t, "testdata/sbom.cdx.json")); !errors.Is(err, scan.ErrNoDB) || !v.IsZero() {
		t.Fatalf("Scan before Update = %v, %v, want zero version and ErrNoDB", v, err)
	}
	if swapped, err := s.Update(t.Context()); err != nil || !swapped {
		t.Fatalf("Update() = %v, %v, want true, nil", swapped, err)
	}

	const (
		musl   = "pkg:apk/alpine/musl@1.2.4-r2?arch=x86_64&distro=3.19.1"
		lodash = "pkg:npm/lodash@4.17.20"
	)
	muslComponent := v0s.Component{PURL: musl, PackageKey: "pkg:apk/alpine/musl", Name: "musl", Version: "1.2.4-r2"}
	lodashComponent := v0s.Component{PURL: lodash, PackageKey: "pkg:npm/lodash", Name: "lodash", Version: "4.17.20"}
	muslFinding := v0s.Finding{VulnerabilityID: "CVE-2025-0001", PURL: musl, PackageKey: "pkg:apk/alpine/musl", InstalledVersion: "1.2.4-r2", FixedVersion: "1.2.4-r3", Status: "fixed", Severity: v0s.SeverityHigh, SeveritySource: "nvd", DataSource: "alpine"}
	lodashFindings := []v0s.Finding{
		{VulnerabilityID: "CVE-2025-0002", PURL: lodash, PackageKey: "pkg:npm/lodash", InstalledVersion: "4.17.20", FixedVersion: "4.17.21", Status: "fixed", Severity: v0s.SeverityMedium, SeveritySource: "ghsa", DataSource: "ghsa"},
		{VulnerabilityID: "GHSA-xxxx-yyyy-zzzz", PURL: lodash, PackageKey: "pkg:npm/lodash", InstalledVersion: "4.17.20", Status: "affected", Severity: v0s.SeverityLow, SeveritySource: "ghsa", DataSource: "ghsa"},
	}
	muslVulnerability := v0s.Vulnerability{
		ID: "CVE-2025-0001", Title: "musl overflow", Description: "A buffer overflow in musl.",
		Severities:  map[string]v0s.Severity{"nvd": v0s.SeverityHigh},
		References:  []string{"https://example.com/CVE-2025-0001"},
		PublishedAt: time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		ModifiedAt:  time.Date(2025, 1, 3, 0, 0, 0, 0, time.UTC),
	}
	lodashVulnerabilities := []v0s.Vulnerability{
		{
			ID: "CVE-2025-0002", Aliases: []string{"GHSA-aaaa-bbbb-cccc"}, Title: "lodash prototype pollution",
			Severities: map[string]v0s.Severity{"ghsa": v0s.SeverityMedium, "nvd": v0s.SeverityCritical},
		},
		{
			ID: "GHSA-xxxx-yyyy-zzzz", Title: "lodash ReDoS",
			Severities: map[string]v0s.Severity{"ghsa": v0s.SeverityLow},
		},
	}
	lodashOnly := v0s.ScanResult{
		Components:      []v0s.Component{lodashComponent},
		Findings:        lodashFindings,
		Vulnerabilities: lodashVulnerabilities,
	}

	tests := []struct {
		name    string
		sbom    string
		want    v0s.ScanResult
		wantErr bool
	}{
		{
			name: "alpine and npm packages under an OCI image",
			sbom: "testdata/sbom.cdx.json",
			want: v0s.ScanResult{
				Components:      []v0s.Component{muslComponent, lodashComponent},
				Findings:        append([]v0s.Finding{muslFinding}, lodashFindings...),
				Vulnerabilities: append([]v0s.Vulnerability{muslVulnerability}, lodashVulnerabilities...),
			},
		},
		{name: "nested component", sbom: "testdata/nested.cdx.json", want: lodashOnly},
		{
			name: "library metadata component with a nested component",
			sbom: "testdata/library-root.cdx.json",
			want: v0s.ScanResult{
				Components:      []v0s.Component{{PURL: "pkg:npm/app@1.0.0", PackageKey: "pkg:npm/app", Name: "app", Version: "1.0.0"}, lodashComponent},
				Findings:        lodashFindings,
				Vulnerabilities: lodashVulnerabilities,
			},
		},
		{name: "purl without version", sbom: "testdata/versionless-purl.cdx.json", want: lodashOnly},
		{
			name: "purl type Trivy cannot match",
			sbom: "testdata/unsupported-purl-type.cdx.json",
			want: v0s.ScanResult{Components: []v0s.Component{{PURL: "pkg:generic/acme/libfoo@1.2", PackageKey: "pkg:generic/acme/libfoo", Name: "libfoo", Version: "1.2"}}},
		},
		{name: "not CycloneDX", sbom: "testdata/spdx.json", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotVersion, err := s.Scan(t.Context(), readFile(t, tt.sbom))
			if !gotVersion.Equal(version) {
				t.Errorf("Scan() version = %v, want %v", gotVersion, version)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatal("Scan() succeeded, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Scan() error: %v", err)
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

func TestUpdateRetriesFailedInstall(t *testing.T) {
	repo := newRegistry(t)
	dir := t.TempDir()
	version := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	digest := pushDB(t, repo, version)
	s, err := scan.New(dir, []string{repo}, discard)
	if err != nil {
		t.Fatal(err)
	}

	// A non-empty directory where the download is moved to makes the install fail.
	blocker := filepath.Join(dir, "db-"+strings.ReplaceAll(digest, ":", "-"))
	if err := os.MkdirAll(filepath.Join(blocker, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if swapped, err := s.Update(t.Context()); err == nil || swapped {
		t.Fatalf("Update() with install blocked = %v, %v, want false and an error", swapped, err)
	}
	if err := os.RemoveAll(blocker); err != nil {
		t.Fatal(err)
	}
	update(t, s, true, version) // the same artifact is installed on retry
}

func TestNewSkipsDBThatFailsToOpen(t *testing.T) {
	repo := newRegistry(t)
	dir := t.TempDir()
	v1 := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	pushDB(t, repo, v1)
	s, err := scan.New(dir, []string{repo}, discard)
	if err != nil {
		t.Fatal(err)
	}
	update(t, s, true, v1)

	// A newer DB with valid metadata but a corrupt database file, as an interrupted install may leave.
	broken := filepath.Join(dir, "db-broken")
	if err := os.Mkdir(broken, 0o755); err != nil {
		t.Fatal(err)
	}
	writeMetadata(t, broken, v1.Add(time.Hour))
	if err := os.WriteFile(filepath.Join(broken, "trivy.db"), []byte("not a bolt database"), 0o644); err != nil {
		t.Fatal(err)
	}

	s, err = scan.New(dir, nil, discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.DBVersion(); !got.Equal(v1) {
		t.Errorf("DBVersion() = %v, want the older DB %v", got, v1)
	}
	if _, err := os.Stat(broken); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("broken DB still present: %v", err)
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

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func writeMetadata(t *testing.T, dir string, updatedAt time.Time) {
	t.Helper()
	meta, err := json.Marshal(map[string]any{"Version": 2, "UpdatedAt": updatedAt, "NextUpdate": updatedAt.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "metadata.json"), meta, 0o644); err != nil {
		t.Fatal(err)
	}
}

// pushDB builds a trivy-db from testdata/fixtures, the way Trivy's internal/dbtest does,
// pushes it to repo as a trivy-db artifact, and returns the artifact's manifest digest.
func pushDB(t *testing.T, repo string, updatedAt time.Time) string {
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
	writeMetadata(t, dir, updatedAt)

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
	img = mutate.MediaType(img, types.OCIManifestSchema1)
	if err := remote.Write(ref, img); err != nil {
		t.Fatal(err)
	}
	digest, err := img.Digest()
	if err != nil {
		t.Fatal(err)
	}
	return digest.String()
}
