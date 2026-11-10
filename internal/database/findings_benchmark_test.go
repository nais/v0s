package database_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
)

// BenchmarkListFindings measures early and deep pages on a tenant-sized inventory:
// 5,000 workloads, 3,200 images, 128,000 stored findings and 200,000 occurrences.
// Run with -benchtime=10x -count=3; timings are evidence, not CI assertions.
func BenchmarkListFindings(b *testing.B) {
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
		INSERT INTO vulnerabilities (id, title, cvss, db_version)
		SELECT 'CVE-' || lpad(n::text, 4, '0'), 'Example vulnerability ' || n,
			'{"nvd":{"v3_score":7.5},"ghsa":{"v3_score":8.1}}', now()
		FROM generate_series(1, 20) n;
		INSERT INTO findings (image_id, vulnerability_id, purl, package_key, installed_version, fixed_version, status, severity)
		SELECT i.id, v.id, 'pkg:npm/package-' || n || '@1', 'pkg:npm/package-' || n,
			'1', '2', 'fixed', 'HIGH'
		FROM images i CROSS JOIN vulnerabilities v CROSS JOIN generate_series(1, 2) n;
		ANALYZE;
	`); err != nil {
		b.Fatal(err)
	}

	for _, workload := range []int{0, 2500, 4500} {
		b.Run(fmt.Sprintf("after_workload_%d", workload), func(b *testing.B) {
			page := database.Page{Size: 1000}
			if workload != 0 {
				cursor := fmt.Sprintf(`{"e":"prod","t":"team-%03d","w":"app-%05d","v":"CVE-0010","p":"pkg:npm/package-1@1"}`, (workload-1)/50, workload)
				page.Token = base64.RawURLEncoding.EncodeToString([]byte(cursor))
			}
			for b.Loop() {
				findings, next, err := db.ListFindings(ctx, database.FindingFilter{}, page)
				if err != nil {
					b.Fatal(err)
				}
				if len(findings) != page.Size || next == "" {
					b.Fatalf("got %d findings, next=%q; want a full page and continuation", len(findings), next)
				}
			}
		})
	}
}
