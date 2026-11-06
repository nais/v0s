package database_test

import (
	"context"
	"slices"
	"testing"

	"github.com/nais/v0s"
	"github.com/nais/v0s/internal/database"
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

// A workload whose image could not be resolved is stored and listed without an image, so that
// it is visible as a coverage gap rather than missing.
func TestUnresolvedWorkload(t *testing.T) {
	ctx := context.Background()
	db := databasetest.New(t)

	resolved := workloadImage("dev", "a", "img-a")
	unresolved := v0s.WorkloadImage{
		Environment: "dev", Team: "team", Workload: "b",
		Reference: "registry/img-b:latest", ResolveError: "tag not found",
	}
	if err := db.SyncWorkloadImages(ctx, "dev", []v0s.WorkloadImage{resolved, unresolved}); err != nil {
		t.Fatal(err)
	}

	got, _, err := db.ListWorkloads(ctx, database.WorkloadFilter{}, database.Page{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("ListWorkloads = %+v, want two workloads", got)
	}
	if a := got[0]; a.Image == nil || a.Image.Name != "img-a" || a.ImageReference != resolved.Reference || a.ResolveError != "" {
		t.Errorf("resolved workload = %+v, want image img-a and reference %q", a, resolved.Reference)
	}
	if b := got[1]; b.Image != nil || b.ImageReference != unresolved.Reference || b.ResolveError != unresolved.ResolveError {
		t.Errorf("unresolved workload = %+v, want no image, reference %q and error %q", b, unresolved.Reference, unresolved.ResolveError)
	}
	if images := queryStrings(t, db, `SELECT name FROM images`); !slices.Equal(images, []string{"img-a"}) {
		t.Errorf("images = %q, want only img-a", images)
	}
}
