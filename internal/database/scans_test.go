package database_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/database/databasetest"
)

func TestClaimScans(t *testing.T) {
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

	tests := []struct {
		name string
		want []string
	}{
		{name: "in use, fetched and outdated", want: []string{`old {"sbom":"old"}`, `unscanned {"sbom":"unscanned"}`}},
		{name: "leased", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobs, err := db.ClaimScans(ctx, v2, 10, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, j := range jobs {
				got = append(got, j.Image.Name+" "+string(j.SBOM))
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("claimed %q, want %q", got, tt.want)
			}
		})
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
		wantEvents   []string
	}{
		{
			name:         "first scan",
			dbVersion:    v1,
			result:       scanResult("CVE-A pkg:x/p1", "CVE-B pkg:x/p1", "CVE-B pkg:x/p1"),
			wantFindings: []string{"CVE-A pkg:x/p1", "CVE-B pkg:x/p1"},
			wantEvents:   []string{"2026-01-01 appeared CVE-A pkg:x/p1", "2026-01-01 appeared CVE-B pkg:x/p1"},
		},
		{
			name:         "newer db",
			dbVersion:    v2,
			result:       scanResult("CVE-B pkg:x/p1", "CVE-C pkg:x/p2"),
			wantFindings: []string{"CVE-B pkg:x/p1", "CVE-C pkg:x/p2"},
			wantEvents: []string{
				"2026-01-01 appeared CVE-A pkg:x/p1", "2026-01-01 appeared CVE-B pkg:x/p1",
				"2026-02-01 appeared CVE-C pkg:x/p2", "2026-02-01 resolved CVE-A pkg:x/p1",
			},
		},
		{
			name:         "older db is a no-op",
			dbVersion:    v1,
			result:       scanResult("CVE-D pkg:x/p3"),
			wantFindings: []string{"CVE-B pkg:x/p1", "CVE-C pkg:x/p2"},
			wantEvents: []string{
				"2026-01-01 appeared CVE-A pkg:x/p1", "2026-01-01 appeared CVE-B pkg:x/p1",
				"2026-02-01 appeared CVE-C pkg:x/p2", "2026-02-01 resolved CVE-A pkg:x/p1",
			},
		},
		{
			name:         "same db is a no-op",
			dbVersion:    v2,
			result:       scanResult("CVE-D pkg:x/p3"),
			wantFindings: []string{"CVE-B pkg:x/p1", "CVE-C pkg:x/p2"},
			wantEvents: []string{
				"2026-01-01 appeared CVE-A pkg:x/p1", "2026-01-01 appeared CVE-B pkg:x/p1",
				"2026-02-01 appeared CVE-C pkg:x/p2", "2026-02-01 resolved CVE-A pkg:x/p1",
			},
		},
	}
	firstSeen := map[string]time.Time{}
	for _, s := range steps {
		if err := db.StoreScan(ctx, id, s.dbVersion, s.result); err != nil {
			t.Fatalf("%s: %v", s.name, err)
		}

		rows, err := db.Pool().Query(ctx, `SELECT vulnerability_id || ' ' || purl, first_seen_at FROM findings ORDER BY 1`)
		if err != nil {
			t.Fatal(err)
		}
		var (
			findings []string
			finding  string
			seen     time.Time
		)
		if _, err := pgx.ForEachRow(rows, []any{&finding, &seen}, func() error {
			if prev, ok := firstSeen[finding]; ok && !prev.Equal(seen) {
				t.Errorf("%s: first_seen_at of %s changed from %v to %v", s.name, finding, prev, seen)
			}
			firstSeen[finding] = seen
			findings = append(findings, finding)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(findings, s.wantFindings) {
			t.Errorf("%s: findings = %q, want %q", s.name, findings, s.wantFindings)
		}

		events := queryStrings(t, db, `
			SELECT to_char(db_version AT TIME ZONE 'UTC', 'YYYY-MM-DD') || ' ' || kind || ' ' || vulnerability_id || ' ' || purl
			FROM finding_events ORDER BY 1`)
		if !slices.Equal(events, s.wantEvents) {
			t.Errorf("%s: events = %q, want %q", s.name, events, s.wantEvents)
		}
	}

	// Components are stored by the first scan only, deduplicated by purl.
	got := queryStrings(t, db, `SELECT purl FROM components ORDER BY purl`)
	if want := []string{"pkg:x/p1"}; !slices.Equal(got, want) {
		t.Errorf("components = %q, want %q", got, want)
	}
	got = queryStrings(t, db, `
		SELECT v.id || ' ' || (v.severities ->> 'nvd') || ' ' || (v.cvss -> 'nvd' ->> 'v3_score') || ' ' ||
			array_to_string(v."references", ',') || ' ' || a.alias
		FROM vulnerabilities v JOIN vulnerability_aliases a ON a.vulnerability_id = v.id
		WHERE v.id = 'CVE-A'`)
	if want := []string{"CVE-A HIGH 7.5 https://example.com/CVE-A GHSA-CVE-A"}; !slices.Equal(got, want) {
		t.Errorf("vulnerability = %q, want %q", got, want)
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
			CVSS:       map[string]v0s.CVSS{"nvd": {V3Score: 7.5}},
			References: []string{"https://example.com/" + id},
		})
		r.Components = append(r.Components, v0s.Component{PURL: purl, PackageKey: purl, Name: purl, Version: "1"})
	}
	return r
}
