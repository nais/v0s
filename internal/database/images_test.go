package database_test

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
)

func TestClaimSBOMFetches(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)

	ids := runImages(t, db, "c1", "due", "fetched", "missing-due", "failed-later", "unused")
	runImages(t, db, "c1", "due", "fetched", "missing-due", "failed-later")
	if err := db.StoreSBOM(ctx, ids["fetched"], []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordSBOMFailure(ctx, ids["missing-due"], v0s.SBOMMissing, "no attestation", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := db.RecordSBOMFailure(ctx, ids["failed-later"], v0s.SBOMFailed, "timeout", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		want []string
	}{
		{name: "due images in use", want: []string{"due pending ", "missing-due missing no attestation"}},
		{name: "leased", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			images, err := db.ClaimSBOMFetches(ctx, 10, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, img := range images {
				got = append(got, fmt.Sprintf("%s %s %s", img.Name, img.SBOMState, img.SBOMError))
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("claimed %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClaimSBOMFetchesConcurrently(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)

	var names []string
	for i := range 50 {
		names = append(names, fmt.Sprintf("img-%d", i))
	}
	runImages(t, db, "c1", names...)

	var (
		wg      sync.WaitGroup
		claimed [2][]v0s.Image
		errs    [2]error
	)
	for i := range claimed {
		wg.Go(func() { claimed[i], errs[i] = db.ClaimSBOMFetches(ctx, 30, time.Minute) })
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	seen := map[int64]bool{}
	for _, images := range claimed {
		for _, img := range images {
			if seen[img.ID] {
				t.Errorf("image %s claimed twice", img.Name)
			}
			seen[img.ID] = true
		}
	}
	if len(seen) != len(names) {
		t.Errorf("claimed %d images, want %d", len(seen), len(names))
	}
}

func TestStoreSBOMKeepsFirst(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	id := runImages(t, db, "c1", "img")["img"]

	for _, doc := range []string{"first", "second"} {
		if err := db.StoreSBOM(ctx, id, []byte(doc)); err != nil {
			t.Fatal(err)
		}
	}
	job, ok, err := db.ClaimScan(ctx, time.Now(), time.Minute)
	if err != nil || !ok {
		t.Fatalf("ClaimScan = %t, %v, want a job", ok, err)
	}
	if got := string(job.SBOM); got != "first" {
		t.Errorf("SBOM = %q, want %q", got, "first")
	}
}

func TestDeleteUnusedImages(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)

	ids := runImages(t, db, "c1", "used-old", "unused-old", "unused-recent")
	runImages(t, db, "c1", "used-old")
	if err := db.StoreSBOM(ctx, ids["unused-old"], []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := db.StoreScan(ctx, ids["unused-old"], time.Now(), scanResult("CVE-1 pkg:x/a")); err != nil {
		t.Fatal(err)
	}
	exec(t, db, `UPDATE images SET last_seen_at = now() - interval '2 days' WHERE name LIKE '%-old'`)

	n, err := db.DeleteUnusedImages(ctx, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("deleted %d images, want 1", n)
	}
	got := queryStrings(t, db, `SELECT name FROM images ORDER BY name`)
	if want := []string{"unused-recent", "used-old"}; !slices.Equal(got, want) {
		t.Errorf("images = %q, want %q", got, want)
	}
	got = queryStrings(t, db, `SELECT image_name || ' ' || vulnerability_id FROM finding_events`)
	if want := []string{"unused-old CVE-1"}; !slices.Equal(got, want) {
		t.Errorf("finding events = %q, want %q", got, want)
	}
}

// workloadImage returns a workload image for image name, with digest "sha256:"+name.
func workloadImage(cluster, workload, name string) v0s.WorkloadImage {
	return v0s.WorkloadImage{
		Cluster:   cluster,
		Namespace: "team",
		Workload:  workload,
		Container: "app",
		OwnerKind: "ReplicaSet",
		ImageName: name,
		Digest:    "sha256:" + name,
	}
}

// runImages makes the named images the only ones running in cluster and returns all image IDs by name.
func runImages(t *testing.T, db *database.DB, cluster string, names ...string) map[string]int64 {
	t.Helper()
	var ws []v0s.WorkloadImage
	for _, name := range names {
		ws = append(ws, workloadImage(cluster, name, name))
	}
	if err := db.SyncWorkloadImages(context.Background(), cluster, ws); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Pool().Query(context.Background(), `SELECT name, id FROM images`)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int64{}
	var (
		name string
		id   int64
	)
	if _, err := pgx.ForEachRow(rows, []any{&name, &id}, func() error { ids[name] = id; return nil }); err != nil {
		t.Fatal(err)
	}
	return ids
}

// queryStrings returns the single text column of query's rows.
func queryStrings(t *testing.T, db *database.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.Pool().Query(context.Background(), query, args...)
	if err != nil {
		t.Fatal(err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func exec(t *testing.T, db *database.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Pool().Exec(context.Background(), query, args...); err != nil {
		t.Fatal(err)
	}
}
