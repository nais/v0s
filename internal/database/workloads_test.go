package database_test

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/database/databasetest"
)

func TestSyncWorkloadImages(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)

	steps := []struct {
		environment string
		ws          []v0s.WorkloadImage
		want        []string
	}{
		{
			environment: "c1",
			ws:          []v0s.WorkloadImage{workloadImage("c1", "a", "img-a"), workloadImage("c1", "b", "img-b"), workloadImage("c1", "b", "img-b")},
			want:        []string{"c1 a img-a", "c1 b img-b"},
		},
		{
			environment: "c2",
			ws:          []v0s.WorkloadImage{workloadImage("c2", "a", "img-a")},
			want:        []string{"c1 a img-a", "c1 b img-b", "c2 a img-a"},
		},
		{
			environment: "c1",
			ws:          []v0s.WorkloadImage{workloadImage("c1", "b", "img-c")},
			want:        []string{"c1 b img-c", "c2 a img-a"},
		},
		{
			environment: "c2",
			want:        []string{"c1 b img-c"},
		},
	}
	for i, s := range steps {
		if err := db.SyncWorkloadImages(ctx, s.environment, s.ws); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
		got := queryStrings(t, db, `
			SELECT w.environment || ' ' || w.name || ' ' || i.name
			FROM workloads w JOIN images i ON i.id = w.image_id
			ORDER BY 1`)
		if !slices.Equal(got, s.want) {
			t.Errorf("step %d: workload images = %q, want %q", i, got, s.want)
		}
	}

	got := queryStrings(t, db, `SELECT name || ' ' || sbom_state FROM images ORDER BY name`)
	want := []string{"img-a pending", "img-b pending", "img-c pending"}
	if !slices.Equal(got, want) {
		t.Errorf("images = %q, want %q", got, want)
	}

	if err := db.SyncWorkloadImages(ctx, "c1", []v0s.WorkloadImage{workloadImage("c2", "a", "img-a")}); err == nil {
		t.Error("sync with a workload image from another environment succeeded, want error")
	}

	// A workload listed twice with different images is an error, and the previous
	// snapshot stays rather than one of the images being picked.
	conflict := []v0s.WorkloadImage{workloadImage("c1", "a", "img-a"), workloadImage("c1", "a", "img-b")}
	if err := db.SyncWorkloadImages(ctx, "c1", conflict); err == nil {
		t.Error("sync with a workload listed with two images succeeded, want error")
	}
	got = queryStrings(t, db, `
		SELECT w.environment || ' ' || w.name || ' ' || i.name
		FROM workloads w JOIN images i ON i.id = w.image_id
		ORDER BY 1`)
	if want := []string{"c1 b img-c"}; !slices.Equal(got, want) {
		t.Errorf("after conflicting sync, workloads = %q, want %q", got, want)
	}
}

func TestSyncWorkloadImagesConcurrently(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)
	// Slow down inserts so that both syncs are in flight at the same time.
	exec(t, db, `
		CREATE FUNCTION slow() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.5); RETURN NULL; END $$;
		CREATE TRIGGER slow BEFORE INSERT ON workloads FOR EACH STATEMENT EXECUTE FUNCTION slow();`)

	var (
		wg   sync.WaitGroup
		errs [2]error
	)
	for i, name := range []string{"img-x", "img-y"} {
		wg.Go(func() {
			errs[i] = db.SyncWorkloadImages(ctx, "c1", []v0s.WorkloadImage{workloadImage("c1", name, name)})
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	got := queryStrings(t, db, `SELECT w.name FROM workloads w ORDER BY 1`)
	if len(got) != 1 {
		t.Errorf("workload images = %q, want one of the two snapshots", got)
	}
}
