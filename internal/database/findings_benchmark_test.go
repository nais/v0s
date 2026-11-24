package database_test

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
)

func newFindingsBenchmark(b *testing.B) *database.DB {
	b.Helper()
	db, url := databasetest.NewWithURL(b)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `
		INSERT INTO images (name, digest)
		SELECT 'registry/app-' || n, 'sha256:' || n FROM generate_series(1, 3200) n;
		INSERT INTO workloads (environment, team, name, image_reference, image_id)
		SELECT 'prod', 'team-' || lpad(((n-1)/50)::text, 3, '0'),
			'app-' || lpad(n::text, 5, '0'), 'registry/app:' || n, (n-1)%3200+1
		FROM generate_series(1, 5000) n;
		INSERT INTO vulnerabilities (id, title, db_version)
		SELECT 'CVE-' || lpad(n::text, 4, '0'), 'Example vulnerability ' || n, now()
		FROM generate_series(1, 20) n;
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, fixed_version, status, severity)
		SELECT i.id, v.id, 'pkg:npm/package-' || n || '@1', 'pkg:npm/package-' || n,
			'1', '2', 'fixed', 'HIGH'
		FROM images i CROSS JOIN vulnerabilities v CROSS JOIN generate_series(1, 2) n;
		INSERT INTO kev (cve, date_added, known_ransomware_campaign)
		VALUES ('CVE-0001', '2026-01-02', false);
		ANALYZE;
	`); err != nil {
		b.Fatal(err)
	}
	return db
}

// BenchmarkListFindings measures early and deep pages on a tenant-sized inventory:
// 5,000 workloads, 3,200 images, 128,000 stored findings and 200,000 occurrences.
// Run with -benchtime=10x -count=3; timings are evidence, not CI assertions.
func BenchmarkListFindings(b *testing.B) {
	db := newFindingsBenchmark(b)
	ctx := context.Background()
	for _, workload := range []int{0, 2500, 4500} {
		b.Run(fmt.Sprintf("after_workload_%d", workload), func(b *testing.B) {
			page := database.Page{Size: 1000}
			if workload != 0 {
				target := fmt.Sprintf("app-%05d", workload)
				for {
					list, err := db.ListFindings(ctx, database.FindingFilter{}, page, database.FindingOrder{})
					if err != nil {
						b.Fatal(err)
					}
					found := false
					for i, f := range list.Findings {
						if f.Workload.Name == target && f.Finding.VulnerabilityID == "CVE-0010" && f.Finding.PURL == "pkg:npm/package-1@1" {
							page.Token = list.Cursors[i]
							found = true
							break
						}
					}
					if found {
						break
					}
					if list.NextPageToken == "" {
						b.Fatal("benchmark cursor boundary not found")
					}
					page.Token = list.NextPageToken
				}
			}
			for b.Loop() {
				list, err := db.ListFindings(ctx, database.FindingFilter{}, page, database.FindingOrder{})
				if err != nil {
					b.Fatal(err)
				}
				if len(list.Findings) != page.Size || list.NextPageToken == "" {
					b.Fatalf("got %d findings, next=%q; want a full page and continuation", len(list.Findings), list.NextPageToken)
				}
			}

		})
	}
}

func BenchmarkListFindingsScopes(b *testing.B) {
	for _, suppressed := range []int{0, 500, 50000} {
		b.Run(fmt.Sprintf("suppressions_%d", suppressed), func(b *testing.B) {
			db := newFindingsBenchmark(b)
			ctx := context.Background()
			if suppressed > 0 {
				if _, err := db.Pool().Exec(ctx, `
					INSERT INTO suppressions (team, environment, workload, image_name,
						package_key, vulnerability_id, state, detail, updated_by)
					SELECT w.team, w.environment, w.name, i.name, 'pkg:npm/package-1',
						v.id, 'accepted_risk', 'benchmark', 'benchmark'
					FROM workloads w JOIN images i ON i.id = w.image_id
					CROSS JOIN vulnerabilities v
					WHERE v.id <= 'CVE-0010'
					ORDER BY v.id, w.team, w.name
					LIMIT $1
				`, suppressed); err != nil {
					b.Fatal(err)
				}
			}
			if _, err := db.Pool().Exec(ctx, "ANALYZE suppressions"); err != nil {
				b.Fatal(err)
			}
			for _, scope := range []struct {
				name   string
				filter database.FindingFilter
			}{
				{name: "tenant"},
				{name: "team", filter: database.FindingFilter{Teams: []string{"team-000"}}},
				{name: "workload", filter: database.FindingFilter{Teams: []string{"team-000"}, Environment: "prod", Workload: "app-00001"}},
			} {
				b.Run(scope.name, func(b *testing.B) {
					want, err := db.CountFindings(ctx, scope.filter, database.GroupByPackageType)
					if err != nil {
						b.Fatal(err)
					}
					for b.Loop() {
						list, err := db.ListFindings(ctx, scope.filter, database.Page{Size: 1000}, database.FindingOrder{})
						if err != nil {
							b.Fatal(err)
						}
						if !slices.Equal(list.PackageTypeCounts, want) {
							b.Fatalf("counts = %v, want %v", list.PackageTypeCounts, want)
						}
					}
				})
			}
		})
	}
}
