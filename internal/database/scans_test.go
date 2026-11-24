package database_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nais/v0s/internal/database/databasetest"
	"github.com/nais/v0s/internal/v0s"
)

func TestNextScan(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	v1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v2 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	ids := runImages(t, db, "c1", "unscanned", "old", "current", "failed", "pending", "unused")
	runImages(t, db, "c1", "unscanned", "old", "current", "failed", "pending")
	for _, name := range []string{"unscanned", "old", "current", "failed", "unused"} {
		if err := db.StoreSBOM(ctx, ids[name], []byte(`{"sbom":"`+name+`"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.StoreScan(ctx, ids["old"], v1, v0s.ScanResult{}); err != nil {
		t.Fatal(err)
	}
	if err := db.StoreScan(ctx, ids["current"], v2, v0s.ScanResult{}); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordScanFailure(ctx, ids["failed"], v2, "boom"); err != nil {
		t.Fatal(err)
	}

	// In use, fetched and outdated, never scanned first. Each is handed out until its result is stored.
	var got []string
	for range 10 {
		j, ok, err := db.NextScan(ctx, v2)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			break
		}
		if again, _, err := db.NextScan(ctx, v2); err != nil || again.Image.ID != j.Image.ID {
			t.Errorf("NextScan before storing %s = %s, %v; want it again", j.Image.Name, again.Image.Name, err)
		}
		got = append(got, j.Image.Name+" "+string(j.SBOM))
		if err := db.StoreScan(ctx, j.Image.ID, v2, v0s.ScanResult{}); err != nil {
			t.Fatal(err)
		}
	}
	if want := []string{`unscanned {"sbom":"unscanned"}`, `old {"sbom":"old"}`}; !slices.Equal(got, want) {
		t.Errorf("scanned %q, want %q", got, want)
	}
}

func TestStoreScan(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	v1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v2 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	id := runImages(t, db, "c1", "img")["img"]

	steps := []struct {
		name         string
		dbVersion    time.Time
		result       v0s.ScanResult
		wantFindings []string
	}{
		{
			name:         "first scan",
			dbVersion:    v1,
			result:       scanResult("CVE-A pkg:x/p1", "CVE-B pkg:x/p1", "CVE-B pkg:x/p1"),
			wantFindings: []string{"CVE-A pkg:x/p1", "CVE-B pkg:x/p1"},
		},
		{
			name:         "newer db",
			dbVersion:    v2,
			result:       scanResult("CVE-B pkg:x/p1", "CVE-C pkg:x/p2"),
			wantFindings: []string{"CVE-B pkg:x/p1", "CVE-C pkg:x/p2"},
		},
		{
			name:         "older db is a no-op",
			dbVersion:    v1,
			result:       scanResult("CVE-D pkg:x/p3"),
			wantFindings: []string{"CVE-B pkg:x/p1", "CVE-C pkg:x/p2"},
		},
		{
			name:         "same db is a no-op",
			dbVersion:    v2,
			result:       scanResult("CVE-D pkg:x/p3"),
			wantFindings: []string{"CVE-B pkg:x/p1", "CVE-C pkg:x/p2"},
		},
	}
	for _, s := range steps {
		if err := db.StoreScan(ctx, id, s.dbVersion, s.result); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}
		findings := queryStrings(t, db, `SELECT vulnerability_id || ' ' || purl FROM findings ORDER BY 1`)
		if !slices.Equal(findings, s.wantFindings) {
			t.Errorf("%s: findings = %q, want %q", s.name, findings, s.wantFindings)
		}
	}

	// Components are stored by the first scan only, deduplicated by purl.
	got := queryStrings(t, db, `SELECT purl FROM components ORDER BY purl`)
	if want := []string{"pkg:x/p1"}; !slices.Equal(got, want) {
		t.Errorf("components = %q, want %q", got, want)
	}
	got = queryStrings(t, db, `
		SELECT v.id || ' ' || (v.severities ->> 'nvd') || ' ' ||
			array_to_string(v."references", ',') || ' ' || a.alias
		FROM vulnerabilities v JOIN vulnerability_aliases a ON a.vulnerability_id = v.id
		WHERE v.id = 'CVE-A'`)
	if want := []string{"CVE-A HIGH https://example.com/CVE-A GHSA-CVE-A"}; !slices.Equal(got, want) {
		t.Errorf("vulnerability = %q, want %q", got, want)
	}
}

func TestRecordScanFailure(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	v1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v2 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	v3 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	id := runImages(t, db, "c1", "img")["img"]
	if err := db.StoreSBOM(ctx, id, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := db.StoreScan(ctx, id, v1, scanResult("CVE-A pkg:x/p1")); err != nil {
		t.Fatal(err)
	}

	state := func() []string {
		t.Helper()
		return queryStrings(t, db, `
			SELECT concat_ws(' ', to_char(i.scanned_db_version AT TIME ZONE 'UTC', 'YYYY-MM-DD'), quote_literal(i.error), f.vulnerability_id)
			FROM images i LEFT JOIN findings f ON f.image_id = i.id ORDER BY 1`)
	}
	claimed := func(dbVersion time.Time) bool {
		t.Helper()
		_, ok, err := db.NextScan(ctx, dbVersion)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	if err := db.RecordScanFailure(ctx, id, v2, "boom"); err != nil {
		t.Fatal(err)
	}
	if got, want := state(), []string{"2026-01-01 'boom' CVE-A"}; !slices.Equal(got, want) {
		t.Errorf("after failure with v2: %q, want findings from v1 kept: %q", got, want)
	}
	if claimed(v2) {
		t.Error("image that failed with v2 handed out again for v2")
	}

	if err := db.StoreScan(ctx, id, v2, scanResult("CVE-B pkg:x/p1")); err != nil {
		t.Fatal(err)
	}
	if got, want := state(), []string{"2026-02-01 '' CVE-B"}; !slices.Equal(got, want) {
		t.Errorf("after successful scan with v2: %q, want %q", got, want)
	}
	if !claimed(v3) {
		t.Error("image not handed out for a newer DB")
	}
}

// TestNextScanAttemptCap checks that an image whose scans never record a result, as when the scan
// kills the process, is given up for that DB version after three attempts.
func TestNextScanAttemptCap(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	v1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v2 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	v3 := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	id := runImages(t, db, "c1", "img")["img"]
	if err := db.StoreSBOM(ctx, id, []byte("{}")); err != nil {
		t.Fatal(err)
	}

	// attempt hands out the image with dbVersion and records nothing, as if the process had died.
	attempt := func(dbVersion time.Time) bool {
		t.Helper()
		_, ok, err := db.NextScan(ctx, dbVersion)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	for i := range 2 {
		if !attempt(v1) {
			t.Fatalf("attempt %d for v1 failed", i+1)
		}
	}
	for i := range 3 {
		if !attempt(v2) {
			t.Fatalf("attempt %d for v2 failed: attempts with v1 must not count for v2", i+1)
		}
	}
	if attempt(v2) {
		t.Error("image handed out a fourth time for v2")
	}
	got := queryStrings(t, db, `SELECT error || ' ' || to_char(scan_failed_db_version AT TIME ZONE 'UTC', 'YYYY-MM-DD') FROM images`)
	if want := []string{"abandoned after 3 attempts 2026-02-01"}; !slices.Equal(got, want) {
		t.Errorf("after the fourth attempt: %q, want %q", got, want)
	}
	if !attempt(v3) {
		t.Error("abandoned image not handed out for a newer DB")
	}
}

func TestStoreScanKeepsNewerVulnerability(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	v1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	v2 := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	ids := runImages(t, db, "c1", "a", "b")

	for _, s := range []struct {
		image     string
		dbVersion time.Time
		title     string
	}{
		{image: "a", dbVersion: v2, title: "from v2"},
		{image: "b", dbVersion: v1, title: "from v1"},
	} {
		r := scanResult("CVE-A pkg:x/p1")
		r.Vulnerabilities[0].Title = s.title
		if err := db.StoreScan(ctx, ids[s.image], s.dbVersion, r); err != nil {
			t.Fatal(err)
		}
	}
	got := queryStrings(t, db, `SELECT title FROM vulnerabilities WHERE id = 'CVE-A'`)
	if want := []string{"from v2"}; !slices.Equal(got, want) {
		t.Errorf("title = %q, want %q", got, want)
	}
}

// scanResult returns a scan result with one finding per "VULN-ID purl" string, the referenced
// vulnerabilities, and their purls as components.
func scanResult(findings ...string) v0s.ScanResult {
	var r v0s.ScanResult
	for _, f := range findings {
		id, purl, _ := strings.Cut(f, " ")
		r.Findings = append(r.Findings, v0s.Finding{
			VulnerabilityID: id, PURL: purl, PackageKey: purl, InstalledVersion: "1", Status: "affected", Severity: v0s.SeverityHigh,
		})
		r.Vulnerabilities = append(r.Vulnerabilities, v0s.Vulnerability{
			ID:         id,
			Aliases:    []string{"GHSA-" + id},
			Severities: map[string]v0s.Severity{"nvd": v0s.SeverityHigh},
			References: []string{"https://example.com/" + id},
		})
		r.Components = append(r.Components, v0s.Component{PURL: purl, PackageKey: purl, Name: purl, Version: "1"})
	}
	return r
}
