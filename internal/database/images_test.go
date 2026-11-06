package database_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
)

func TestDueSBOMFetches(t *testing.T) {
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

	images, err := db.DueSBOMFetches(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, img := range images {
		got = append(got, fmt.Sprintf("%s %s %s", img.Name, img.SBOMState, img.Error))
	}
	slices.Sort(got)
	if want := []string{"due pending ", "missing-due missing no attestation"}; !slices.Equal(got, want) {
		t.Errorf("due %q, want %q", got, want)
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
	job, ok, err := db.NextScan(ctx, time.Now())
	if err != nil || !ok {
		t.Fatalf("NextScan = %t, %v, want a job", ok, err)
	}
	if got := string(job.SBOM); got != "first" {
		t.Errorf("SBOM = %q, want %q", got, "first")
	}
}

func TestDeleteUnusedImages(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)

	ids := runImages(t, db, "c1", "used", "unused")
	if err := db.StoreSBOM(ctx, ids["unused"], []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := db.StoreScan(ctx, ids["unused"], time.Now(), scanResult("CVE-1 pkg:x/a")); err != nil {
		t.Fatal(err)
	}
	runImages(t, db, "c1", "used")

	n, err := db.DeleteUnusedImages(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("deleted %d images, want 1", n)
	}
	got := queryStrings(t, db, `SELECT name FROM images ORDER BY name`)
	if want := []string{"used"}; !slices.Equal(got, want) {
		t.Errorf("images = %q, want %q", got, want)
	}
	if got := queryStrings(t, db, `SELECT vulnerability_id FROM findings`); len(got) != 0 {
		t.Errorf("findings of deleted image = %q, want none", got)
	}

	// A fetch or scan that was running when the image was deleted records nothing.
	if err := db.StoreSBOM(ctx, ids["unused"], []byte("{}")); err != nil {
		t.Errorf("StoreSBOM of deleted image: %v", err)
	}
	if err := db.StoreScan(ctx, ids["unused"], time.Now().Add(time.Hour), scanResult("CVE-1 pkg:x/a")); err != nil {
		t.Errorf("StoreScan of deleted image: %v", err)
	}
	if got := queryStrings(t, db, `SELECT name FROM images ORDER BY name`); !slices.Equal(got, []string{"used"}) {
		t.Errorf("images after storing for a deleted one = %q, want only used", got)
	}
}

// workloadImage returns a workload image for image name, with digest "sha256:"+name.
func workloadImage(environment, workload, name string) v0s.WorkloadImage {
	return v0s.WorkloadImage{
		Environment: environment,
		Team:        "team",
		Workload:    workload,
		Reference:   name + ":1",
		ImageName:   name,
		Digest:      "sha256:" + name,
	}
}

// runImages makes the named images the only ones in use in environment and returns all image IDs by name.
func runImages(t *testing.T, db *database.DB, environment string, names ...string) map[string]int64 {
	t.Helper()
	var ws []v0s.WorkloadImage
	for _, name := range names {
		ws = append(ws, workloadImage(environment, name, name))
	}
	if err := db.SyncWorkloadImages(context.Background(), environment, ws); err != nil {
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
