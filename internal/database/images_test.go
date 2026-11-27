package database_test

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nais/v0s/internal/database"
	"github.com/nais/v0s/internal/database/databasetest"
	"github.com/nais/v0s/internal/v0s"
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

func TestImageErrorCode(t *testing.T) {
	ctx := t.Context()
	db := databasetest.New(t)
	id := runImages(t, db, "dev", "img")["img"]
	rejected := v0s.ImageErrorCodeAttestationRejected
	check := func(state v0s.SBOMState, message string, code v0s.ImageErrorCode) {
		t.Helper()
		workloads, _, err := db.ListWorkloads(ctx, database.WorkloadFilter{}, database.Page{})
		if err != nil || len(workloads) != 1 || workloads[0].Image == nil {
			t.Fatalf("workloads=%+v, err=%v", workloads, err)
		}
		img := workloads[0].Image
		if img.SBOMState != state || img.Error != message || img.ErrorCode != code {
			t.Errorf("image=%+v; want state=%s, error=%q, code=%q", img, state, message, code)
		}
	}
	fail := func() {
		t.Helper()
		if err := db.RecordSBOMFailureWithCode(ctx, id, v0s.SBOMFailed, "SBOM attestation was rejected", rejected, time.Now().Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	fail()
	check(v0s.SBOMFailed, "SBOM attestation was rejected", rejected)
	due, err := db.DueSBOMFetches(ctx, 10)
	if err != nil || len(due) != 1 || due[0].ErrorCode != rejected {
		t.Fatalf("due=%+v, err=%v; want rejected code", due, err)
	}
	if err := db.RecordSBOMFailure(ctx, id, v0s.SBOMMissing, "No SBOM attestation was found", time.Now()); err != nil {
		t.Fatal(err)
	}
	check(v0s.SBOMMissing, "No SBOM attestation was found", v0s.ImageErrorCodeUnspecified)
	if err := db.RecordSBOMFailureWithCode(ctx, id, v0s.SBOMFailed, "invalid", v0s.ImageErrorCode("unknown"), time.Now()); err == nil {
		t.Fatal("unknown error code must violate the database constraint")
	}
	fail()
	if err := db.StoreSBOM(ctx, id, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	check(v0s.SBOMFetched, "", v0s.ImageErrorCodeUnspecified)
	fail()
	check(v0s.SBOMFetched, "", v0s.ImageErrorCodeUnspecified)
	job, ok, err := db.NextScan(ctx, time.Now())
	if err != nil || !ok || job.Image.ErrorCode != v0s.ImageErrorCodeUnspecified {
		t.Fatalf("NextScan=%+v, %t, %v; want cleared code", job, ok, err)
	}
	version := time.Now()
	exec(t, db, `UPDATE images SET error_code = 'attestation_rejected' WHERE id = $1`, id)
	if err := db.RecordScanFailure(ctx, id, version, "scan failed"); err != nil {
		t.Fatal(err)
	}
	check(v0s.SBOMFetched, "scan failed", v0s.ImageErrorCodeUnspecified)
	exec(t, db, `UPDATE images SET error_code = 'attestation_rejected' WHERE id = $1`, id)
	if err := db.StoreScan(ctx, id, version.Add(time.Hour), v0s.ScanResult{}); err != nil {
		t.Fatal(err)
	}
	check(v0s.SBOMFetched, "", v0s.ImageErrorCodeUnspecified)
}

func TestMigrateImageErrorCode(t *testing.T) {
	ctx := t.Context()
	db, url := databasetest.NewWithURL(t)
	id := runImages(t, db, "dev", "img")["img"]
	exec(t, db, `
		ALTER TABLE images DROP COLUMN error_code;
		DELETE FROM schema_migrations WHERE version = 4;
		UPDATE images SET sbom_state = 'failed', error = 'previous failure';`)
	db.Close()
	if err := database.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	migrated, err := database.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	workloads, _, err := migrated.ListWorkloads(ctx, database.WorkloadFilter{}, database.Page{})
	if err != nil || len(workloads) != 1 || workloads[0].Image == nil {
		t.Fatalf("migrated workloads=%+v, err=%v", workloads, err)
	}
	img := workloads[0].Image
	if img.Error != "previous failure" || img.ErrorCode != v0s.ImageErrorCodeUnspecified {
		t.Errorf("migrated image=%+v; want preserved failure with unspecified code", img)
	}
	if err := migrated.RecordSBOMFailureWithCode(ctx, id, v0s.SBOMFailed, "SBOM attestation was rejected", v0s.ImageErrorCodeAttestationRejected, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := database.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	if got := queryStrings(t, migrated, `SELECT error_code FROM images WHERE id = $1`, id); !slices.Equal(got, []string{"attestation_rejected"}) {
		t.Errorf("repeated migration changed recorded code: %q", got)
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
